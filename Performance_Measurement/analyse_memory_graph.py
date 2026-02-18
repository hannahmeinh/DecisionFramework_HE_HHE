"""analyse_memory_graph.py"""

import os
import re
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class MemoryData:
    timestamps: List[datetime]
    ram_mb: List[float]
    swap_kb: List[float]
    is_batch: List[bool]
    init_events: List[Tuple[float, str]] = None
    init_events_with_swap: List[Tuple[float, float, str]] = None
    max_ram_peak_mb: float = 0
    peak_timestamp: Optional[datetime] = None
    init_timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.init_events is None:
            self.init_events = []
        if self.init_events_with_swap is None:
            self.init_events_with_swap = []


@dataclass
class FileMetadata:
    component: str
    variant: str
    timestamp: str
    batch_nr: int
    batch_size: int
    int_size: int
    filepath: str


class LogParser:
    
    INIT_PATTERNS = [
        'Client Initialisation Keys_Params Start',
        'Client Initialisation Keys_Params End',
        'Client Initialisation ZeroMQ Start',
        'Client Initialisation ZeroMQ End',
        'Server Initialisation Keys_Params Start',
        'Server Initialisation Keys_Params End',
        'Server Initialisation ZeroMQ Start',
        'Server Initialisation ZeroMQ End',
        'TTP Initialisation Keys_Params Start',
        'TTP Initialisation Keys_Params End',
        'TTP Initialisation ZeroMQ Start',
        'TTP Initialisation ZeroMQ End'
    ]
    
    # Parses a memory log file and returns all extracted measurements as a MemoryData object.
    def parse(self, filepath: str) -> MemoryData:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        measurements = defaultdict(dict)
        in_batch = False
        current_init_event = None
        
        max_ram_peak_kb = 0
        peak_timestamp = None
        
        init_events = []
        init_events_with_swap = []
        
        initialized_timestamp = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            timestamp = self._extract_timestamp(line)
            if not timestamp:
                continue
            
            if " initialized" in line and not initialized_timestamp:
                initialized_timestamp = timestamp
            
            init_event = self._check_init_event(line)
            if init_event:
                current_init_event = init_event
            
            if "Start Batch Processing" in line or "Batch Start" in line:
                in_batch = True
            elif "End Batch Processing" in line or "Batch End" in line:
                in_batch = False
            
            measurements[timestamp]['batch'] = in_batch
            
            if "RAM:" in line and "RAM Peak:" not in line:
                ram_kb = self._extract_value(line, r'RAM: (\d+) kB')
                if ram_kb is not None:
                    measurements[timestamp]['ram'] = ram_kb
                    
                    if current_init_event:
                        swap_kb = measurements[timestamp].get('swap', 0)
                        init_events.append((ram_kb / 1024, current_init_event))
                        init_events_with_swap.append((ram_kb / 1024, swap_kb, current_init_event))
                        current_init_event = None
            
            if "SWAP:" in line:
                swap_kb = self._extract_value(line, r'SWAP: (\d+) kB')
                if swap_kb is not None:
                    measurements[timestamp]['swap'] = swap_kb
            
            if "RAM Peak:" in line:
                peak_kb = self._extract_value(line, r'RAM Peak: (\d+) kB')
                if peak_kb and peak_kb > max_ram_peak_kb:
                    max_ram_peak_kb = peak_kb
                    peak_timestamp = timestamp
        
        return self._build_memory_data(
            measurements, init_events, init_events_with_swap, max_ram_peak_kb, peak_timestamp, initialized_timestamp
        )
    
    # Extracts and returns the datetime timestamp from a single log line.
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
        if match:
            return datetime.fromisoformat(match.group(1))
        return None
    
    # Extracts and returns a numeric value from a log line using the given regex pattern.
    def _extract_value(self, line: str, pattern: str) -> Optional[int]:
        match = re.search(pattern, line)
        return int(match.group(1)) if match else None
    
    # Checks whether a log line contains a known initialization event and returns its type.
    def _check_init_event(self, line: str) -> Optional[str]:
        for pattern in self.INIT_PATTERNS:
            if pattern in line:
                if 'Keys_Params' in pattern:
                    return 'keys_params'
                elif 'ZeroMQ Start' in pattern:
                    return 'zeromq_start'
                elif 'ZeroMQ End' in pattern:
                    return 'zeromq_end'
        return None
    
    # Assembles and returns a MemoryData object from the parsed measurement dictionaries and event lists.
    def _build_memory_data(self, measurements: dict, init_events: List, init_events_with_swap: List,
                          max_ram_peak_kb: int, peak_timestamp, initialized_timestamp) -> MemoryData:
        sorted_times = sorted(measurements.keys())
        
        timestamps = []
        ram_mb = []
        swap_kb = []
        is_batch = []
        
        for ts in sorted_times:
            if initialized_timestamp and ts < initialized_timestamp:
                continue
                
            m = measurements[ts]
            if 'ram' in m:
                timestamps.append(ts)
                ram_mb.append(m['ram'] / 1024)
                swap_kb.append(m.get('swap', 0))
                is_batch.append(m.get('batch', False))
        
        return MemoryData(
            timestamps=timestamps,
            ram_mb=ram_mb,
            swap_kb=swap_kb,
            is_batch=is_batch,
            init_events=init_events,
            init_events_with_swap=init_events_with_swap,
            max_ram_peak_mb=max_ram_peak_kb / 1024,
            peak_timestamp=peak_timestamp,
            init_timestamp=initialized_timestamp
        )


class GraphPlotter:
    
    # Initializes the plotter with the target Raspberry Pi type for time axis scaling.
    def __init__(self, pi_type: str = "3b"):
        self.pi_type = pi_type
    
    # Generates and saves a scatter plot of RAM usage over time for the given component.
    def plot_ram(self, data: MemoryData, metadata: FileMetadata, output_path: str):
        plt.figure(figsize=(12, 6))
        
        ram = data.ram_mb[:-1] if len(data.ram_mb) > 1 else data.ram_mb
        times = data.timestamps[:-1] if len(data.timestamps) > 1 else data.timestamps
        batches = data.is_batch[:-1] if len(data.is_batch) > 1 else data.is_batch
        
        start_time = times[0]
        seconds = [(t - start_time).total_seconds() for t in times]
        
        time_data, xlabel = self._prepare_time_axis(seconds, metadata)
        
        for t in time_data:
            plt.axvline(x=t, color='gray', linestyle='-', linewidth=0.5, alpha=0.3, zorder=1)
        
        plt.scatter(time_data, ram, color='blue', s=20, alpha=0.8)
        
        if data.init_events:
            self._add_init_markers(data.init_events)
        
        if (data.max_ram_peak_mb > 0 and metadata.component == 'ttp' 
            and metadata.variant == 'HHE'):
            self._add_peak_marker(data, start_time, time_data, times, metadata)
        
        self._fill_background(time_data, ram, batches, 'blue')
        
        self._configure_graph(
            f"{metadata.component.upper()} {'Hybrid' if metadata.variant == 'HHE' else 'Plain'} - RAM Usage Over Time",
            xlabel, "RAM Usage (MB)"
        )
        
        plt.ylim(bottom=0)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    # Generates and saves a scatter plot of SWAP usage over time, with special unit scaling for client HE.
    def plot_swap(self, data: MemoryData, metadata: FileMetadata, output_path: str):
        plt.figure(figsize=(12, 6))
        
        swap = data.swap_kb[:-1] if len(data.swap_kb) > 1 else data.swap_kb
        times = data.timestamps[:-1] if len(data.timestamps) > 1 else data.timestamps
        batches = data.is_batch[:-1] if len(data.is_batch) > 1 else data.is_batch
        
        ylabel = "SWAP Usage (kB)"
        if metadata.component == 'client' and metadata.variant == 'HE':
            if self.pi_type == "3b":
                swap = [s * 1024 for s in swap]
                ylabel = "SWAP Usage (Bytes)"
            elif self.pi_type == "zero":
                swap = [s / 1024 for s in swap]
                ylabel = "SWAP Usage (MB)"
        
        start_time = times[0]
        seconds = [(t - start_time).total_seconds() for t in times]
        
        time_data, xlabel = self._prepare_time_axis(seconds, metadata)
        
        plt.scatter(time_data, swap, color='orange', s=20, alpha=0.8)
        
        self._fill_background(time_data, swap, batches, 'orange')
        
        self._configure_graph(
            f"{metadata.component.upper()} {'Hybrid' if metadata.variant == 'HHE' else 'Plain'} - SWAP Usage Over Time",
            xlabel, ylabel
        )
        
        plt.ylim(bottom=0)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    # Generates and saves a stacked area graph of combined RAM and SWAP usage, intended for client HE.
    def plot_stacked_ram_swap(self, data: MemoryData, metadata: FileMetadata, output_path: str):
        plt.figure(figsize=(12, 6))
        
        ram = data.ram_mb[:-1] if len(data.ram_mb) > 1 else data.ram_mb
        swap_kb = data.swap_kb[:-1] if len(data.swap_kb) > 1 else data.swap_kb
        times = data.timestamps[:-1] if len(data.timestamps) > 1 else data.timestamps
        batches = data.is_batch[:-1] if len(data.is_batch) > 1 else data.is_batch
        
        swap_mb = [s / 1024 for s in swap_kb]
        
        total_memory = [r + s for r, s in zip(ram, swap_mb)]
        
        start_time = times[0]
        seconds = [(t - start_time).total_seconds() for t in times]
        
        time_data, xlabel = self._prepare_time_axis(seconds, metadata)
        
        plt.fill_between(time_data, ram, color='blue', alpha=0.6, label='RAM')
        
        plt.fill_between(time_data, ram, total_memory, color='orange', alpha=0.6, label='SWAP')
        
        for t in time_data:
            plt.axvline(x=t, color='navy', linestyle='-', linewidth=0.8, alpha=0.7, zorder=10)
        
        for i in range(len(time_data) - 1):
            if batches[i]:
                plt.fill_between(time_data[i:i+2], 0, [total_memory[i], total_memory[i+1]], 
                               color='black', alpha=0.15, linewidth=0)
        
        if data.init_events_with_swap:
            self._add_init_markers_with_swap(data.init_events_with_swap, metadata)
        
        if data.max_ram_peak_mb > 0 and metadata.component == 'ttp' and metadata.variant == 'HHE':
            self._add_peak_marker(data, start_time, time_data, times, metadata)
        
        self._configure_graph(
            f"{metadata.component.upper()} {'Hybrid' if metadata.variant == 'HHE' else 'Plain'} - Stacked RAM + SWAP Usage Over Time",
            xlabel, "Memory Usage (MB)"
        )
        
        plt.legend(loc='upper left', fontsize=10)
        
        plt.ylim(bottom=0)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    # Generates and saves a stacked area graph showing RAM and SWAP together with boundary lines for clarity.
    def plot_ram_swap_stacked(self, data: MemoryData, metadata: FileMetadata, output_path: str):
        plt.figure(figsize=(12, 6))
        
        ram_mb = data.ram_mb[:-1] if len(data.ram_mb) > 1 else data.ram_mb
        swap_kb = data.swap_kb[:-1] if len(data.swap_kb) > 1 else data.swap_kb
        times = data.timestamps[:-1] if len(data.timestamps) > 1 else data.timestamps
        batches = data.is_batch[:-1] if len(data.is_batch) > 1 else data.is_batch
        
        swap_mb = [s / 1024 for s in swap_kb]
        
        start_time = times[0]
        seconds = [(t - start_time).total_seconds() for t in times]
        time_data, xlabel = self._prepare_time_axis(seconds, metadata)
        
        plt.fill_between(time_data, 0, ram_mb, color='blue', alpha=0.6, label='RAM')
        
        total_memory = [ram + swap for ram, swap in zip(ram_mb, swap_mb)]
        plt.fill_between(time_data, ram_mb, total_memory, color='orange', alpha=0.6, label='SWAP')
        
        plt.plot(time_data, ram_mb, color='blue', linewidth=1, alpha=0.8)
        plt.plot(time_data, total_memory, color='darkorange', linewidth=1, alpha=0.8)
        
        if data.init_events:
            self._add_init_markers(data.init_events)
        
        if (data.max_ram_peak_mb > 0 and metadata.component == 'ttp' 
            and metadata.variant == 'HHE'):
            self._add_peak_marker(data, start_time, time_data, times, metadata)
        
        plt.legend(loc='upper left', fontsize=10)
        
        self._configure_graph(
            f"{metadata.component.upper()} {'Hybrid' if metadata.variant == 'HHE' else 'Plain'} - RAM + SWAP Usage (Stacked)",
            xlabel, "Memory Usage (MB)"
        )
        
        plt.ylim(bottom=0)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
    
    # Scales the time axis values and returns the appropriate unit label based on the component and Pi type.
    def _prepare_time_axis(self, seconds: List[float], 
                          metadata: FileMetadata) -> Tuple[List, str]:
        if metadata.component == 'server':
            time_data = [s / 3600 for s in seconds]
            return time_data, 'Time (Hours)'
        
        if self.pi_type == "zero":
            time_data = []
            for s in seconds:
                if s <= 50:
                    time_data.append(s * 2 / 50)
                else:
                    time_data.append(2 + (s - 50) / 5)
            return time_data, 'Time'
        
        return seconds, 'Time (Seconds)'
    
    # Draws horizontal lines on the graph marking each initialization event at its corresponding RAM level.
    def _add_init_markers(self, init_events: List[Tuple]):
        for ram_mb, event_type in init_events:
            if event_type == 'keys_params':
                color, style = 'purple', '-'
            elif event_type == 'zeromq_start':
                color, style = 'darkgreen', ':'
            elif event_type == 'zeromq_end':
                color, style = 'darkgreen', '--'
            else:
                continue
            
            plt.axhline(y=ram_mb, color=color, linestyle=style, linewidth=2.5, 
                       alpha=0.9, zorder=10)
    
    # Draws horizontal lines on a stacked graph at the combined RAM+SWAP height for each initialization event.
    def _add_init_markers_with_swap(self, init_events_with_swap: List[Tuple], metadata: FileMetadata):
        for ram_mb, swap_kb, event_type in init_events_with_swap:
            swap_mb = swap_kb / 1024
            total_mb = ram_mb + swap_mb
            
            if event_type == 'keys_params':
                color, style = 'purple', '-'
            elif event_type == 'zeromq_start':
                color, style = 'darkgreen', ':'
            elif event_type == 'zeromq_end':
                color, style = 'darkgreen', '--'
            else:
                continue
            
            plt.axhline(y=total_mb, color=color, linestyle=style, linewidth=2.5, 
                       alpha=0.9, zorder=10)
    
    # Draws a red dashed line on TTP HHE graphs indicating the peak RAM value reached.
    def _add_peak_marker(self, data: MemoryData, start_time: datetime,
                        time_data: List, timestamps: List, metadata: FileMetadata):
        peak_seconds = (data.peak_timestamp - start_time).total_seconds()
        
        if metadata.component == 'server':
            peak_time = peak_seconds / 3600
        else:
            peak_time = peak_seconds
        
        peak_index = None
        for i, ts in enumerate(timestamps[:-1]):
            ts_seconds = (ts - start_time).total_seconds()
            ts_time = ts_seconds / 3600 if metadata.component == 'server' else ts_seconds
            if ts_time >= peak_time:
                peak_index = i
                break
        
        if peak_index is not None and peak_index > 0:
            start_x = time_data[peak_index - 1]
            plt.plot([start_x, peak_time], [data.max_ram_peak_mb, data.max_ram_peak_mb],
                    color='red', linestyle='--', linewidth=2, alpha=0.8)
    
    # Fills the graph background with color, using higher opacity during batch processing periods.
    def _fill_background(self, time_data: List, values: List, 
                        is_batch: List, color: str):
        for i in range(len(time_data) - 1):
            alpha = 0.5 if is_batch[i] else 0.3
            plt.fill_between(time_data[i:i+2], values[i:i+2], 
                           alpha=alpha, color=color)
    
    # Applies standard title, axis labels, grid, and layout settings to the current graph.
    def _configure_graph(self, title: str, xlabel: str, ylabel: str):
        plt.title(title, fontsize=14, fontweight='bold')
        plt.xlabel(xlabel, fontsize=12)
        plt.ylabel(ylabel, fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.xlim(left=0)
        plt.tight_layout()


class FileFinder:
    
    FILENAME_PATTERN = (
        r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})_'
        r'(HHE|HE)_BatchNr:(\d+)_BatchSize:(\d+)_IntSize:(\d+)_'
        r'(client|server|ttp)_(HHE|HE)'
    )
    
    # Scans a directory for memory log files and returns the most recent file per component/variant pair.
    def find_latest_files(self, data_dir: str) -> Dict[str, FileMetadata]:
        if not os.path.exists(data_dir):
            return {}
        
        file_groups = defaultdict(list)
        
        for filename in os.listdir(data_dir):
            if not filename.endswith('.txt'):
                continue
            
            match = re.search(self.FILENAME_PATTERN, filename)
            if not match:
                continue
            
            timestamp, variant, batch_nr, batch_size, int_size, component, _ = match.groups()
            
            metadata = FileMetadata(
                component=component,
                variant=variant,
                timestamp=timestamp,
                batch_nr=int(batch_nr),
                batch_size=int(batch_size),
                int_size=int(int_size),
                filepath=os.path.join(data_dir, filename)
            )
            
            key = f"{component}_{variant}"
            file_groups[key].append(metadata)
        
        latest_files = {}
        for key, files in file_groups.items():
            latest = max(files, key=lambda f: f.timestamp)
            latest_files[key] = latest
        
        return latest_files


class MemoryGraphAnalyzer:
    
    # Initializes the analyzer with input/output directories, Pi type, and sets up all required sub-components.
    def __init__(self, data_dir: str = "data_memory", 
                 output_dir: str = "data_graphs", pi_type: str = "3b"):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.pi_type = pi_type
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_dir = os.path.join(output_dir, timestamp)
        os.makedirs(self.run_dir, exist_ok=True)
        
        self.parser = LogParser()
        self.plotter = GraphPlotter(pi_type)
        self.finder = FileFinder()
    
    # Runs the full analysis pipeline by finding, parsing, and plotting memory graphs for all log files.
    def run(self):
        print(f"Memory Graph Analyzer")
        print(f"Pi Type: {self.pi_type}")
        print(f"Output: {self.run_dir}\n")
        
        files = self.finder.find_latest_files(self.data_dir)
        
        if not files:
            print("No log files found!")
            return
        
        print(f"Found {len(files)} components\n")
        
        for key, metadata in files.items():
            print(f"Processing: {key} ({metadata.timestamp})")
            
            data = self.parser.parse(metadata.filepath)
            
            if not data.timestamps:
                print(f"  Warning: No valid data\n")
                continue
            
            base_name = f"{metadata.component}_{metadata.variant}"
            
            if metadata.component == 'client' and metadata.variant == 'HE':
                stacked_path = os.path.join(self.run_dir, f"{base_name}_stacked.png")
                self.plotter.plot_stacked_ram_swap(data, metadata, stacked_path)
                print(f"  ✓ Stacked RAM+SWAP graph")
            else:
                ram_path = os.path.join(self.run_dir, f"{base_name}_ram.png")
                self.plotter.plot_ram(data, metadata, ram_path)
                print(f"  ✓ RAM graph")
            
            print()
        
        print(f"Complete! Graphs saved to: {self.run_dir}")


if __name__ == "__main__":
    PI_TYPE = "3b"  # Options: "3b", "zero"
    
    analyzer = MemoryGraphAnalyzer(
        data_dir="data_memory",
        output_dir="data_graphs", 
        pi_type=PI_TYPE
    )
    
    analyzer.run()