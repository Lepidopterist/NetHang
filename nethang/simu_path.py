"""
Network Simulation Path Management

This module provides a mechanism for managing network simulation paths.

Author: Hang Yin
Date: 2025-05-19
"""

import subprocess
import re
import yaml
import os
import time
import json
from . import app, CONFIG_PATH, CONFIG_FILE, MODELS_FILE, PATHS_FILE, IPT_LOCK_FILE, TC_LOCK_FILE, PATHS_LOCK_FILE
import multiprocessing
from dataclasses import dataclass
from typing import Optional, Dict, List
from nethang.proc_lock import ProcLock
from nethang.traffic_monitor import TrafficMonitor
from nethang.extensions import socketio

@dataclass
class SimuSettings:
    """Network simulation settings for a direction (uplink/downlink)"""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

        if hasattr(self, 'restrict_settings') and self.restrict_settings:
            try:
                for key, value in self.restrict_settings.items():
                    if value == None or value == '':
                        value = self.get_default_value(key)
                        self.restrict_settings[key] = value
            except Exception as e:
                app.logger.error(f"Error in SimuSettings: {e}")

    def get_default_value(self, key):
        if key == 'rate_limit':
            return 1000000
        elif key == 'qdepth':
            return 1000
        elif key == 'loss':
            return 0.0
        elif key == 'delay':
            return 0
        elif key == 'jitter':
            return 0
        elif key == 'loss_type':
            return 'off'
        elif key == 'latency_type':
            return 'off'
        elif key == 'throttle_type':
            return 'off'
        else:
            app.logger.info(f"Not implemented key: {key}")

    def __eq__(self, other):
        return (
            self.mode == other.mode and \
            self.restrict_settings['rate_limit'] == other.restrict_settings['rate_limit'] and \
            self.restrict_settings['qdepth'] == other.restrict_settings['qdepth'] and \
            self.restrict_settings['loss'] == other.restrict_settings['loss'] and \
            self.restrict_settings['delay'] == other.restrict_settings['delay'] and \
            self.restrict_settings['jitter'] == other.restrict_settings['jitter'] and \
            self.restrict_settings['loss_type'] == other.restrict_settings['loss_type'] and \
            self.restrict_settings['latency_type'] == other.restrict_settings['latency_type'] and \
            self.restrict_settings['throttle_type'] == other.restrict_settings['throttle_type']
        )

    def to_dict(self):
        """Convert the SimuSettings object to a dictionary"""
        return self.restrict_settings

@dataclass
class FilterSettings:
    """Filter settings for a network path"""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __eq__(self, other):
        return self.protocol == other.protocol and self.lan_ip == other.lan_ip and self.lan_port == other.lan_port and self.wan_ip == other.wan_ip and self.wan_port == other.wan_port and self.mark == other.mark

class SimuPath:
    """Represents a network simulation path with filter and simulation settings"""
    def __init__(self, filter_settings: FilterSettings, mode: str, model: str, status: str,
                 uplink_settings: SimuSettings, downlink_settings: SimuSettings):
        self.filter = filter_settings
        self.mode = mode # 'model', 'custom'
        self.model = model # models.yaml
        self.status = status # "active" or "inactive"
        self.uplink_settings = uplink_settings
        self.downlink_settings = downlink_settings
        self.simu_proc = None
        self.__direction = {
            'uplink':{
                'from':SimuPathManager.lan_ifname,
                'to':SimuPathManager.wan_ifname,
                'dir':'s',
            },
            'downlink':{
                'from':SimuPathManager.wan_ifname,
                'to':SimuPathManager.lan_ifname,
                'dir':'d',
            }
        }

    def __eq__(self, other):
        return self.filter == other.filter

    def is_active(self):
        return self.status == "active"

    def _cleanup(self, direction_ : str):
        """Cleanup the path by removing traffic control"""
        app.logger.info(f"Cleaning up path {self.filter.mark} {direction_}")
        if hasattr(self, 'filter'):
            iface = self.__direction[direction_]['to']
            handle = SimuPathManager.handle_name
            host_num = str(self.filter.mark)

            with ProcLock(TC_LOCK_FILE):
                SimuPathManager.run_cmd(['tc', 'filter', 'del', 'dev', iface, 'parent', f'{handle}:',
                    'handle', host_num, 'protocol', 'ip', 'pref', str(SimuPathManager.PRIO), 'fw'])
                SimuPathManager.run_cmd(['tc', 'class', 'del', 'dev', iface, 'classid', f'{handle}:{host_num}'])
                SimuPathManager.run_cmd(['tc', 'qdisc', 'del', 'dev', iface, 'parent', f'{handle}:{host_num}',
                    'handle', host_num])
        else:
            app.logger.error(f'Cannot delete rules: filter not available')

        self.status = "inactive"

    def _init_tc(self, direction_ : str):
        """Initialize traffic control for a direction"""
        app.logger.info(f"Initializing traffic control for {direction_}")
        iface = self.__direction[direction_]['to']
        handle = SimuPathManager.handle_name

        with ProcLock(TC_LOCK_FILE):
            SimuPathManager.run_cmd(['tc', 'qdisc', 'add', 'dev', iface, 'root', 'handle', f'{handle}:',
                'htb', 'default', '0xffff', 'direct_qlen', '1000'])
            SimuPathManager.run_cmd(['tc', 'class', 'add', 'dev', iface, 'parent', f'{handle}:',
                'classid', f'{handle}:ffff', 'htb', 'rate', f'{SimuPathManager.MAX_RATE}kbit', 'quantum', '60000'])

    def _apply_tc(self, direction_ : str, opt : str = 'add',
            rate_limit : int = 1000000, rate_ceil : int = 1000000,
            rate_burst : int = 0, rate_cburst : int = 0,
            qdepth : int = 1000,
            loss : float = 0.0,
            delay : int = 0,
            jitter : int = 0,
            jitter_dist : str = 'normal',
            loss_type : str = 'off',
            latency_type : str = 'off',
            throttle_type : str = 'off'
            ):

        class_args_ = ['htb']
        if throttle_type == 'off':
            rate_limit = SimuPathManager.MAX_RATE

        # If rate_limit is greater than MAX_RATE, using MAX_RATE as rate
        # Otherwise, using rate_limit as rate
        if rate_limit >= SimuPathManager.MAX_RATE:
            class_args_ += ['rate', '{}Gbit'.format(SimuPathManager.MAX_RATE / 1000000)]
        else:
            class_args_ += ['rate', '{}Kbit'.format(rate_limit)]

        # If rate_ceil is greater than or equal to MAX_RATE, using rate_limit as ceil
        # Otherwise, using rate_ceil as ceil
        if rate_ceil >= SimuPathManager.MAX_RATE:
            class_args_ += ['ceil', '{}Kbit'.format(rate_limit)]
        else:
            class_args_ += ['ceil', '{}Kbit'.format(rate_ceil)]

        # If rate_burst is less than or equal to 0, using rate_limit / 80 as burst
        # Otherwise, using rate_burst as burst
        if rate_burst <= 0:
            class_args_ += ['burst', '{}KB'.format(round(rate_limit / 80, 2))]
        else:
            class_args_ += ['burst', '{}KB'.format(rate_burst)]

        # If rate_cburst is less than or equal to 0, using rate_limit / 80 as cburst
        # Otherwise, using rate_cburst as cburst
        if rate_cburst <= 0:
            class_args_ += ['cburst', '{}KB'.format(round(rate_limit / 80, 2))]
        else:
            class_args_ += ['cburst', '{}KB'.format(rate_cburst)]

        netem_args_ = ['limit', str(qdepth)]

        if latency_type != 'off':
            # If jitter-reorder-off is selected (jitter > 0 and latency_type == 'jitter-reorder-off'),
            # use slot for jitter instead of delay+jitter approach
            use_slot_for_jitter = (jitter > 0 and latency_type == 'jitter-reorder-off')

            if use_slot_for_jitter:
                min_delay, max_delay = self.__get_slot_jitter_param(jitter)

                # Use slot for jitter
                netem_args_ += ['delay', f'{delay}ms', 'slot', f'{min_delay}ms', f'{max_delay}ms']
            else:
                # Use delay + jitter approach if latency_type is not 'jitter-reorder-off'
                delay_, jitter_ = self.__get_delay_jitter_param(delay, jitter)
                if delay_ != 0 or jitter_ != 0:
                    netem_args_ += ['delay', f'{delay_}ms']
                    if jitter_ != 0:
                        netem_args_ += [f'{jitter_}ms', 'distribution', jitter_dist]
                # Set slot to 0 0 to make sure slot is not used
                netem_args_ += ['slot', '0', '0']

        if loss_type != 'off':
            if loss_type == 'random':
                netem_args_ += ['loss', f'{loss:.6f}%']
            else:
                probability_good2bad, probability_bad2good = self.__get_loss_state_param(loss / 100.0, loss_type)
                netem_args_ += ['loss', 'gemodel', f'{probability_good2bad*100:.6f}%', f'{probability_bad2good*100:.6f}%']

        app.logger.info(f"class_args: {class_args_}")
        app.logger.info(f"netem_args: {netem_args_}")

        iface = self.__direction[direction_]['to']
        handle = SimuPathManager.handle_name
        host_num = str(self.filter.mark)

        with ProcLock(TC_LOCK_FILE):
            SimuPathManager.run_cmd(['tc', 'class', opt, 'dev', iface, 'parent', f'{handle}:',
                'classid', f'{handle}:{host_num}'] + class_args_ + ['quantum', '60000'])
            SimuPathManager.run_cmd(['tc', 'qdisc', opt, 'dev', iface, 'parent', f'{handle}:{host_num}',
                'handle', f'{host_num}:', 'netem'] + netem_args_)
            if opt == 'add':
                SimuPathManager.run_cmd(['tc', 'filter', 'add', 'dev', iface, 'parent', f'{handle}:',
                    'prio', str(SimuPathManager.PRIO), 'protocol', 'ip', 'handle', host_num, 'fw',
                    'flowid', f'{handle}:{host_num}'])

    def _run_custom(self):
        """Run custom simulation"""

        app.logger.info(f"Running custom simulation for PATH {self.filter.mark}")

        for direction in ['uplink', 'downlink']:
            self._cleanup(direction)

        if self.uplink_settings.mode != 'bypass':
            self._set_rule('uplink', 'add', self.uplink_settings.to_dict())
        else:
            app.logger.info(f"Bypassing uplink for PATH {self.filter.mark}")
            self._cleanup('uplink')

        if self.downlink_settings.mode != 'bypass':
            self._set_rule('downlink', 'add', self.downlink_settings.to_dict())
        else:
            app.logger.info(f"Bypassing downlink for PATH {self.filter.mark}")
            self._cleanup('downlink')

    def _run_model(self):
        app.logger.info(f"Running model simulation for PATH {self.filter.mark}")
        try:
            if self.model not in SimuPathManager().models:
                raise ValueError(f'Case {self.model} not found, please check available models, exit ...')
            model_ = SimuPathManager().get_model_settings(self.model)
        except Exception as e:
            raise e

        # At first cleanup
        for direction in ['uplink', 'downlink']:
            self._cleanup(direction)

        model_global = model_.get('global', {})
        model_timeline = model_.get('timeline', [])

        if not model_timeline:
            # Static model
            for direction in ['uplink', 'downlink']:
                self._set_rule(direction, 'add', model_global[direction])
        else:
            # Dynamic model
            is_first_timeslot : bool = True
            while True:
                for model_timeslot in model_timeline:

                    merged_model = SimuPathManager.merge_dicts(model_global, model_timeslot)
                    app.logger.info(f"merged_model: {json.dumps(merged_model, indent=2)}")

                    if is_first_timeslot:
                        opt_ = 'add'
                        is_first_timeslot = False
                    else:
                        opt_ = 'change'

                    for direction in ['uplink', 'downlink']:
                        self._set_rule(direction, opt_, merged_model[direction])

                    if 'duration' in model_timeslot:
                        # Maybe need high precision sleep
                        time.sleep(model_timeslot['duration'])

    def _set_rule(self, direction : str, opt : str, config : dict):
        """Set traffic control rules using provided parameters"""

        app.logger.info(f"set_rule: {direction} {opt} {config}")

        if opt == 'add':
            self._init_tc(direction)
            self._cleanup(direction)

        self._apply_tc(
            direction,
            opt,
            rate_limit = config.get('rate_limit', SimuPathManager.MAX_RATE),
            qdepth = config.get('qdepth', 1000),
            loss = config.get('loss', 0.0),
            delay = config.get('delay', 0),
            jitter = config.get('jitter', 0),
            jitter_dist = config.get('jitter_dist', 'normal'),
            loss_type = config.get('loss_type', 'off'),
            latency_type = config.get('latency_type', 'off'),
            throttle_type = config.get('throttle_type', 'off')
        )

    def _simu_path_worker(self):
        """Run tc command for path activation"""
        app.logger.info(f"Running simulation for PATH {self.filter.mark}")

        try:
            if self.mode == 'custom':
                self._run_custom()
            elif self.mode == 'model':
                self._run_model()
            else:
                raise ValueError(f"Invalid mode: {self.mode}")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to set up traffic control: {e}")

    def activate(self):
        """Activate the path by setting up traffic control"""
        app.logger.info(f"Activating path {self.filter.mark}")
        try:
            # Create the path in system by creating a new iptables rule
            self.create()

            # Set up traffic control for both directions.
            #
            # Explicitly use the 'fork' start method rather than whatever the
            # platform/Python-version default is. On 'spawn' (which newer
            # CPython versions have moved toward by default on some
            # platforms), the child is a fresh interpreter that re-imports
            # the whole nethang package to reconstruct enough state to call
            # the target - which re-runs nethang/__init__.py's module-level
            # code, rebuilding a brand-new SimuPathManager() singleton that
            # runs reset_all_paths() and deactivates every path it finds
            # marked active in paths.yaml, undoing the rule/tc state this
            # same activate() call just created. 'fork' has the child
            # inherit the parent's already-initialized memory directly, with
            # no re-import and no re-running of any initialization code.
            fork_ctx = multiprocessing.get_context('fork')
            self.simu_proc = fork_ctx.Process(target=self._simu_path_worker, args=(), daemon=True)
            self.simu_proc.start()
            self.status = "active"
        except Exception as e:
            raise RuntimeError(f"Failed to activate path: {e}")

    def deactivate(self):
        """Deactivate the path by removing traffic control"""
        app.logger.info(f"Deactivating path {self.filter.mark}")
        try:
            if self.simu_proc:
                self.simu_proc.terminate()

            # Delete the path in system by deleting the iptables rule
            self.delete()
        finally:
            for direction in ['uplink', 'downlink']:
                self._cleanup(direction)
            self.status = "inactive"

    def _build_filter_args(self, direction_ : str) -> List[str]:
        """Build the iptables match arguments (IPs/protocol/ports) for a direction"""
        args = []

        if self.filter.lan_ip:
            args += ['-s', self.filter.lan_ip] if direction_ == 'uplink' else ['-d', self.filter.lan_ip]

        if self.filter.wan_ip:
            args += ['-d', self.filter.wan_ip] if direction_ == 'uplink' else ['-s', self.filter.wan_ip]

        if self.filter.protocol in ['udp', 'tcp']:
            args += ['-p', self.filter.protocol]

            lan_port_ = self._format_port(self.filter.lan_port)
            if lan_port_:
                args += ['--sport', lan_port_] if direction_ == 'uplink' else ['--dport', lan_port_]

            wan_port_ = self._format_port(self.filter.wan_port)
            if wan_port_:
                args += ['--dport', wan_port_] if direction_ == 'uplink' else ['--sport', wan_port_]

        return args

    def create(self):
        """ Create the path in system by creating a new iptables rule """

        def create_iptables_rule(direction_ : str):
            with ProcLock(IPT_LOCK_FILE):
                SimuPathManager.run_cmd(['iptables', '-w', '5', '-t', 'mangle', '-A', 'FORWARD',
                    '-i', self.__direction[direction_]['from'], '-o', self.__direction[direction_]['to'],
                    *self._build_filter_args(direction_),
                    '-j', 'MARK', '--set-mark', str(self.filter.mark)])

        create_iptables_rule('uplink')
        create_iptables_rule('downlink')

    def delete(self):
        """Delete the path in system by deleting the iptables rule"""
        def delete_iptables_rule(direction_ : str):
            with ProcLock(IPT_LOCK_FILE):
                SimuPathManager.run_cmd(['iptables', '-w', '5', '-t', 'mangle', '-D', 'FORWARD',
                    '-i', self.__direction[direction_]['from'], '-o', self.__direction[direction_]['to'],
                    *self._build_filter_args(direction_),
                    '-j', 'MARK', '--set-mark', str(self.filter.mark)])

        delete_iptables_rule('uplink')
        delete_iptables_rule('downlink')

    @staticmethod
    def _format_port(port) -> Optional[str]:
        """Validate a port filter value and format it for iptables --sport/--dport.

        Accepts either a single port number (e.g. '8080') or a port range
        in the 'start:end' format (e.g. '8000:9000'), matching the formats
        iptables itself accepts for --sport/--dport. Returns None for
        empty/'Any' values or anything that fails validation.
        """
        if not port or port == 'Any':
            return None

        port = str(port).strip()

        def is_valid_port_num(value: str) -> bool:
            return value.isdigit() and 0 < int(value) < 65536

        if ':' in port:
            start, sep, end = port.partition(':')
            if not is_valid_port_num(start) or not is_valid_port_num(end):
                return None
            if int(start) > int(end):
                return None
            return '{}:{}'.format(start, end)

        if not is_valid_port_num(port):
            return None
        return port

    def __get_delay_jitter_param(self, input_delay, input_jitter):
        delay_ = input_delay if input_delay != None else 0
        jitter_ = input_jitter if input_jitter != None else 0

        if jitter_ == 0:
            return delay_, jitter_

        # Delay must be greater than 0, otherwise jitter will not work in netem
        delay_ = delay_ if delay_ != 0 else 1

        # Make the jitter's literal value closer to the observed value in statistics
        return delay_, int(jitter_ / 2)

    def __get_slot_jitter_param( self, input_jitter: float, slot_time: float = 20.0 ):
        """
        Generate a tc netem command that simulates jitter WITHOUT packet reordering
        using slot-based delay.

        Args:
            input_jitter: Target jitter (± range, milliseconds)
            slot_time: Slot interval; smaller = finer jitter resolution (default: 20.0ms)

        Returns:
            tuple: (slot_time, max_delay)
        """

        # max_delay chosen so that mean deviation ≈ input_jitter
        max_delay = (input_jitter + slot_time) * 2

        return slot_time, max_delay

    def __get_loss_state_param(self, loss_rate: float, loss_type: str = 'random'):
        """
        Generate tc netem Markov loss commands with the same overall loss rate
        but different burst characteristics.

        Args:
            loss_rate: overall packet loss rate (0 < loss_rate < 1)
            loss_type: loss type, 'random', 'burst-low', 'burst-medium', 'burst-high'

        Returns:
            tuple: (probability_good2bad, probability_bad2good)
        """

        if not (0 < loss_rate < 1):
            raise ValueError("loss_rate must be in (0, 1)")

        # Average burst lengths for each profile
        profiles = {
            "random": 1.0,     # almost i.i.d
            "burst-low": 3.0,  # mild correlation
            "burst-medium": 10.0, # typical bad network
            "burst-high": 50.0 # severe burst loss
        }

        if loss_type not in profiles:
            raise ValueError(f"Invalid loss type: {loss_type}")

        probability_bad2good = 1.0 / profiles[loss_type]
        probability_good2bad = loss_rate * probability_bad2good / (1.0 - loss_rate)

        return probability_good2bad, probability_bad2good

    @classmethod
    def from_dict(cls, data: Dict) -> 'SimuPath':
        """Create a SimuPath instance from a dictionary"""
        return cls(
            filter_settings=FilterSettings(**data['filter_settings']),
            mode=data['simu_settings']['mode'],
            model=data['simu_settings']['model'],
            status=data['status'],
            uplink_settings=SimuSettings(**data['simu_settings']['uplink']),
            downlink_settings=SimuSettings(**data['simu_settings']['downlink'])
        )

class SimuPathManager:
    """Manages network simulation paths"""
    _instance = None

    PRIO = 2
    OVERHEAD = 0
    MAX_RATE = 1000000 # 32Gbps
    handle_name = '9527'
    lan_ifname = None
    wan_ifname = None
    mark_range = (9528, 9560)

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SimuPathManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.load_config()

        self.paths: Dict[int, SimuPath] = {}
        self.refresh_paths()
        self.reset_all_paths()

        self.models = self.load_models()['models']
        self.traffic_monitor = TrafficMonitor(
            interval=1, # Seems it is not necessary to make it configurable
            lan_iface=SimuPathManager.lan_ifname,
            wan_iface=SimuPathManager.wan_ifname,
            id_range=SimuPathManager.mark_range,
            stats_callback=SimuPathManager.emit_chart_data
        )

        self._initialized = True

    def refresh_paths(self):
        """Refresh paths by loading from paths.yaml"""
        self.paths.clear()
        for path in self.load_paths():
            self.paths[path['id']] = SimuPath.from_dict(path)

    def load_models(self):
        try:
            if os.path.exists(MODELS_FILE):
                with open(MODELS_FILE, 'r') as f:
                    models = yaml.safe_load(f)
                    if 'models' in models:
                        return models
                    else:
                        return {'models': {}}
            else:
                return {'models': {}}
        except Exception as e:
            app.logger.error(f"Error loading models: {e}")
            return {'models': {}}

    def load_config(self):
        """Load configuration from config.yaml"""
        if os.path.exists(CONFIG_FILE):
            config = {}
            with open(CONFIG_FILE, 'r') as f:
                config = yaml.safe_load(f)
                if config:
                    SimuPathManager.lan_ifname = config.get('lan_interface', '') if 'lan_interface' in config else ''
                    SimuPathManager.wan_ifname = config.get('wan_interface', '') if 'wan_interface' in config else ''
                    return config
                else:
                    SimuPathManager.lan_ifname = ''
                    SimuPathManager.wan_ifname = ''
                    return {
                        'lan_interface': '',
                        'wan_interface': '',
                    }
        else:
            SimuPathManager.lan_ifname = ''
            SimuPathManager.wan_ifname = ''
            return {
                'lan_interface': '',
                'wan_interface': '',
            }

    def save_config(self, config):
        """Save configuration to config.yaml"""
        os.makedirs(CONFIG_PATH, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(config, f)
        self.emit_config_update()  # Emit config update event

    def load_paths(self) -> List:
        """Load paths from paths.yaml"""
        if os.path.exists(PATHS_FILE):
            try:
                with open(PATHS_FILE, 'r') as f:
                    paths_data = yaml.safe_load(f)
                    if paths_data is None:
                        paths_data = []
                    return paths_data
            except yaml.YAMLError as e:
                app.logger.error(f"Error parsing paths.yaml: {e}")
                # If the file is corrupted, create a new one with empty paths
                paths = []
                self.save_paths(paths)
                return paths
        return []

    def save_paths(self, paths):
        """Save paths to paths.yaml"""
        os.makedirs(CONFIG_PATH, exist_ok=True)
        with open(PATHS_FILE, 'w') as f:
            yaml.dump(paths, f)
        self.emit_config_update()  # Emit config update event

    def deactivate_all_paths(self):
        """Deactivate all paths"""
        for path in self.paths.values():
            path.deactivate()

    def reset_all_paths(self):
        """Reset all paths according to the config"""

        # Deactivate all paths
        self.deactivate_all_paths()

        # Update paths.yaml
        with ProcLock(PATHS_LOCK_FILE):
            paths_data = self.load_paths()
            for p in paths_data:
                p['status'] = 'inactive'

            self.save_paths(paths_data)

    def add_to_path_config(self, path: SimuPath):
        """Add a path to paths.yaml"""
        with ProcLock(PATHS_LOCK_FILE):
            paths_data = self.load_paths()
            paths_data.append(path)
            self.save_paths(paths_data)

    def update_path_config(self, id: int, path) -> bool:
        """Update a path in paths.yaml. Returns whether a matching path was found."""
        with ProcLock(PATHS_LOCK_FILE):
            paths_data = self.load_paths()
            found = False
            for i, p in enumerate(paths_data):
                if int(p['id']) == id:
                    paths_data[i] = path
                    found = True
                    break

            if not found:
                return False

            self.save_paths(paths_data)
        self.refresh_paths()
        return True

    def delete_from_path_config(self, id: int):
        """Delete a path from paths.yaml"""
        with ProcLock(PATHS_LOCK_FILE):
            paths_data = self.load_paths()
            for p in paths_data:
                if int(p['id']) == id:
                    paths_data.remove(p)
                    break
            self.save_paths(paths_data)

    def get_path_config(self, id: int) -> SimuPath:
        """Get a path from paths.yaml"""
        paths_data = self.load_paths()
        for p in paths_data:
            if int(p['id']) == id:
                return p
        return None

    def add_path(self, path):
        """Add a path in system by creating a new iptables rule and save it to paths.yaml"""
        self.paths[path['id']] = SimuPath.from_dict(path)
        self.add_to_path_config(path)

    def delete_path(self, id: int):
        """Delete a path in system by deleting the iptables rule and save it to paths.yaml"""
        if id not in self.paths:
            raise ValueError(f"Path with id {id} not found")

        del self.paths[id]
        self.delete_from_path_config(id)

    def activate_path(self, id: int):
        """Activate a path by id"""
        if id not in self.paths:
            raise ValueError(f"Path with id {id} not found")

        self.paths[id].activate()

        # Update paths.yaml
        with ProcLock(PATHS_LOCK_FILE):
            paths_data = self.load_paths()
            for p in paths_data:
                if int(p['id']) == id:
                    p['status'] = 'active'
                    break
            self.save_paths(paths_data)
        self.traffic_monitor.start()

    def deactivate_path(self, id: int):
        """Deactivate a path by id"""
        if id not in self.paths:
            raise ValueError(f"Path with id {id} not found")

        self.paths[id].deactivate()

        # Update paths.yaml
        with ProcLock(PATHS_LOCK_FILE):
            paths_data = self.load_paths()
            for p in paths_data:
                if int(p['id']) == id:
                    p['status'] = 'inactive'
                    break
            self.save_paths(paths_data)

        if len(self.get_active_paths()) == 0:
            self.traffic_monitor.stop()

    def get_active_paths(self) -> List[SimuPath]:
        """Get all active paths"""
        return [path for path in self.paths.values() if path.status == 'active']

    def is_path_active(self, id: int) -> bool:
        """Check if a path is active by id"""
        pass

    def get_paths(self) -> List[SimuPath]:
        """Get all paths"""
        return list(self.paths.values())

    def get_model_settings(self, model_name: str) -> Optional[Dict]:
        """Get settings for a specific model"""
        return self.models.get(model_name)

    @staticmethod
    def emit_chart_data(chart_data_callback):
        """Send chart data to all connected clients."""
        socketio.emit('update_chart', {
            'labels': chart_data_callback['labels'],
            'data': chart_data_callback['data']
        })

    @staticmethod
    def emit_config_update():
        """Emit configuration update event to all connected clients."""
        socketio.emit('config_updated')

    @staticmethod
    def run_cmd(cmd : List[str], mute : bool = True) -> str:
        """Run a system command given as an argv list (no shell involved).

        Commands are executed directly via subprocess rather than a shell
        string, so values coming from user input (IPs, ports, etc.) can
        never be interpreted as shell syntax. Failures are swallowed by
        default (matching prior behavior, since callers routinely invoke
        best-effort cleanup commands that are expected to fail).
        """
        app.logger.debug(f"Run command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            app.logger.warning(f"Failed to run command {' '.join(cmd)}: {e}")
            return ''

        if not mute and result.returncode != 0:
            app.logger.debug(f"Command {' '.join(cmd)} exited {result.returncode}: {result.stderr.strip()}")

        return result.stdout

    @staticmethod
    def merge_dicts(base: dict, update: dict) -> dict:
        """
        Recursively merge two dictionaries, with values from update taking precedence
        """
        merged = base.copy()
        for key, value in update.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = SimuPathManager.merge_dicts(merged[key], value)
            elif value is not None:  # Only update if value is not None
                merged[key] = value
        return merged