# analyse_time_memory.py

import os
import re
from datetime import datetime
from typing import Dict, List
from collections import defaultdict


class AnalyseTimeMemory:

    # Initializes the analyser with directories for time data, memory data, and analysis output.
    def __init__(self, data_time_dir: str = "data_time", data_memory_dir: str = "data_memory", 
                 analysis_dir: str = "data_analysed"):
        self.data_time_dir = data_time_dir
        self.data_memory_dir = data_memory_dir
        self.analysis_dir = analysis_dir
        
        if not os.path.exists(self.analysis_dir):
            os.makedirs(self.analysis_dir)
    
    # Scans the time and memory directories for matching file pairs and returns them grouped by component and variant.
    def get_matching_files(self) -> Dict[str, Dict[str, str]]:
        file_pairs = {}
        
        if not os.path.exists(self.data_time_dir):
            print(f"Warning: Directory {self.data_time_dir} does not exist.")
            return file_pairs
        
        for filename in os.listdir(self.data_time_dir):
            if not filename.endswith(".txt"):
                continue
            
            memory_file = os.path.join(self.data_memory_dir, filename)
            if os.path.exists(memory_file):
                match = re.search(r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})_(HHE|HE)_BatchNr:(\d+)_BatchSize:(\d+)_IntSize:(\d+)_(client|server|ttp)_(HHE|HE)', filename)
                
                if match:
                    timestamp, variant, batch_nr, batch_size, int_size, component, _ = match.groups()
                    
                    key = f"{component}_{variant}"
                    
                    if key not in file_pairs:
                        file_pairs[key] = []
                    
                    file_pairs[key].append({
                        'time_file': os.path.join(self.data_time_dir, filename),
                        'memory_file': memory_file,
                        'filename': filename,
                        'timestamp': timestamp,
                        'variant': variant,
                        'batch_nr': int(batch_nr),
                        'batch_size': int(batch_size),
                        'int_size': int(int_size),
                        'component': component
                    })
        
        for key in file_pairs:
            file_pairs[key].sort(key=lambda x: x['timestamp'], reverse=True)
        
        return file_pairs
    
    # Extracts a clean operation name by removing start/end markers and timestamp prefixes from event text.
    def extract_operation_name(self, event_text: str) -> str:
        if " Start" in event_text:
            op_name = event_text.split(" Start")[0].strip()
        elif " End" in event_text:
            op_name = event_text.split(" End")[0].strip()
        else:
            op_name = event_text.strip()
        
        if " : " in op_name:
            op_name = op_name.split(" : ")[0].strip()
        
        return op_name
    
    # Maps an operation name to a predefined category based on keywords in the name.
    def categorize_operation(self, op_name: str) -> str:
        op_lower = op_name.lower()
        
        if "encryption" in op_lower or "kreyvium" in op_lower:
            return "Encryption"
        elif "decryption" in op_lower:
            return "Decryption"
        elif "transciphering" in op_lower:
            return "Transciphering"
        elif "batch transmission" in op_lower:
            return "Batch Transmission"
        elif "batch" in op_lower:
            return "Batch"
        elif "integer" in op_lower:
            return "Integer"
        elif "initialized" in op_lower:
            return "Initialization"
        else:
            return op_name
    
    # Parses a time log file and returns structured data containing operations with their start and end timestamps.
    def parse_time_file(self, filepath: str) -> Dict:
        with open(filepath, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        data = {'operations': [], 'initialization': None}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) : (.+)$', line)
            if not timestamp_match:
                continue
            
            timestamp_str = timestamp_match.group(1)
            event = timestamp_match.group(2)
            timestamp = datetime.fromisoformat(timestamp_str)
            
            if "initialized" in event.lower():
                data['initialization'] = {'timestamp': timestamp}
            elif " Start" in event:
                op_name = self.extract_operation_name(event)
                data['operations'].append({
                    'name': op_name,
                    'category': self.categorize_operation(op_name),
                    'start_time': timestamp
                })
            elif " End" in event:
                op_name = self.extract_operation_name(event)
                for op in reversed(data['operations']):
                    if op['name'] == op_name and 'end_time' not in op:
                        op['end_time'] = timestamp
                        break
        
        return data
    
    # Parses a memory log file and returns structured data containing operations with their start and end memory snapshots.
    def parse_memory_file(self, filepath: str) -> Dict:
        with open(filepath, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        data = {'operations': [], 'initialization': None}
        current_timestamp = None
        current_memory = {}
        current_event = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) : (.+)$', line)
            if timestamp_match:
                current_timestamp = timestamp_match.group(1)
                current_event = timestamp_match.group(2)
                current_memory = {}
                continue
            
            if current_timestamp:
                if "SWAP:" in line:
                    match = re.search(r'SWAP: (\d+) kB', line)
                    if match:
                        current_memory['swap'] = int(match.group(1))
                elif "RAM Peak:" in line:
                    match = re.search(r'RAM Peak: (\d+) kB', line)
                    if match:
                        current_memory['ram_peak'] = int(match.group(1))
                elif "RAM:" in line and "Peak" not in line:
                    match = re.search(r'RAM: (\d+) kB', line)
                    if match:
                        current_memory['ram'] = int(match.group(1))
                        
                        if current_event and "initialized" in current_event.lower():
                            data['initialization'] = current_memory.copy()
                        elif current_event and " Start" in current_event:
                            op_name = self.extract_operation_name(current_event)
                            data['operations'].append({
                                'name': op_name,
                                'category': self.categorize_operation(op_name),
                                'start_memory': current_memory.copy()
                            })
                        elif current_event and " End" in current_event:
                            op_name = self.extract_operation_name(current_event)
                            for op in reversed(data['operations']):
                                if op['name'] == op_name and 'end_memory' not in op:
                                    op['end_memory'] = current_memory.copy()
                                    break
        
        return data
    
    # Combines parsed time and memory data with file metadata into a unified metrics dictionary grouped by operation category.
    def calculate_metrics(self, time_data: Dict, memory_data: Dict, metadata: Dict) -> Dict:
        metrics = {
            'component': metadata['component'],
            'variant': metadata['variant'],
            'batch_nr': metadata['batch_nr'],
            'batch_size': metadata['batch_size'],
            'int_size': metadata['int_size'],
            'filename': metadata['filename'],
            'initialization': {},
            'operations_by_category': defaultdict(list)
        }
        
        if memory_data.get('initialization'):
            init_mem = memory_data['initialization']
            metrics['initialization'] = {
                'swap': init_mem.get('swap', 0),
                'ram': init_mem.get('ram', 0),
                'ram_peak': init_mem.get('ram_peak', 0)
            }
        
        for time_op in time_data['operations']:
            if 'start_time' not in time_op or 'end_time' not in time_op:
                continue
            
            duration = (time_op['end_time'] - time_op['start_time']).total_seconds()
            
            mem_op = next((m for m in memory_data['operations'] 
                          if m['name'] == time_op['name'] and 'start_memory' in m and 'end_memory' in m), None)
            
            op_metrics = {
                'duration': duration,
                'ram_diff': 0,
                'swap_diff': 0,
                'ram_peak': 0
            }
            
            if mem_op:
                op_metrics['ram_diff'] = mem_op['end_memory'].get('ram', 0) - mem_op['start_memory'].get('ram', 0)
                op_metrics['swap_diff'] = mem_op['end_memory'].get('swap', 0) - mem_op['start_memory'].get('swap', 0)
                op_metrics['ram_peak'] = mem_op['end_memory'].get('ram_peak', 0)
            
            category = time_op['category']
            metrics['operations_by_category'][category].append(op_metrics)
        
        return metrics
    
    # Computes average duration, RAM diff, swap diff, and peak RAM across a list of operation metric dictionaries.
    def calculate_averages(self, operations: List[Dict]) -> Dict:
        if not operations:
            return {
                'count': 0,
                'avg_duration': 0,
                'avg_ram_diff': 0,
                'avg_swap_diff': 0,
                'max_ram_peak': 0
            }
        
        return {
            'count': len(operations),
            'avg_duration': sum(op['duration'] for op in operations) / len(operations),
            'avg_ram_diff': sum(op['ram_diff'] for op in operations) / len(operations),
            'avg_swap_diff': sum(op['swap_diff'] for op in operations) / len(operations),
            'max_ram_peak': max(op['ram_peak'] for op in operations)
        }
    
    # Converts a duration in seconds to a human-readable hours/minutes/seconds string.
    def format_time(self, seconds: float) -> str:
        total_seconds = int(seconds)
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        secs = total_seconds % 60
        return f"({hours} h {minutes} m {secs} s)"
    
    # Converts a memory value from kilobytes to megabytes.
    def kb_to_mb(self, kb: float) -> float:
        return kb / 1024.0
    
    # Formats a memory value in kilobytes as a string showing both megabytes and kilobytes.
    def format_memory(self, kb: float) -> str:
        mb = self.kb_to_mb(kb)
        return f"{mb:.2f} MB ({kb:.0f} kB)"
    
    # Generates a formatted performance report string from a list of metrics grouped by component and variant.
    def generate_report(self, all_metrics: List[Dict]) -> str:
        report = []
        report.append("=" * 100)
        report.append("PERFORMANCE ANALYSIS")
        report.append("=" * 100)
        report.append("")
        
        grouped = {}
        for metrics in all_metrics:
            key = f"{metrics['component']}_{metrics['variant']}"
            if key not in grouped:
                grouped[key] = metrics
        
        for key, metrics in sorted(grouped.items()):
            report.append(f"\n{'=' * 100}")
            report.append(f"COMPONENT: {metrics['component'].upper()} | VARIANT: {metrics['variant']}")
            report.append(f"{'=' * 100}")
            report.append(f"Source file: {metrics['filename']}")
            report.append(f"Batch count: {metrics['batch_nr']} | Batch size: {metrics['batch_size']} | Integer size: {metrics['int_size']} bit")
            report.append("")
            
            if metrics['initialization']:
                report.append("AFTER INITIALIZATION:")
                report.append("-" * 100)
                init = metrics['initialization']
                report.append(f"SWAP: {self.format_memory(init['swap'])}")
                report.append(f"RAM: {self.format_memory(init['ram'])}")
                report.append(f"RAM Peak: {self.format_memory(init['ram_peak'])}")
                report.append("")
            
            report.append("OPERATION AVERAGES:")
            report.append("-" * 100)
            
            category_order = [
                'Batch',
                'Batch Transmission',
                'Integer',
                'Encryption',
                'Transciphering',
                'Decryption'
            ]
            
            for category in category_order:
                if category in metrics['operations_by_category']:
                    ops = metrics['operations_by_category'][category]
                    avg = self.calculate_averages(ops)
                    
                    if avg['count'] > 0:
                        report.append(f"\n{category} Average (n={avg['count']}):")
                        report.append(f"   Time diff: {avg['avg_duration']:.6f} s {self.format_time(avg['avg_duration'])}")
                        report.append(f"   SWAP diff: {self.format_memory(avg['avg_swap_diff'])}")
                        report.append(f"   RAM diff: {self.format_memory(avg['avg_ram_diff'])}")
                        report.append(f"   RAM Peak: {self.format_memory(avg['max_ram_peak'])}")
            
            report.append("")
        
        report.append("=" * 100)
        report.append("END OF ANALYSIS")
        report.append("=" * 100)
        
        return "\n".join(report)
    
    # Orchestrates the full analysis pipeline by loading, parsing, and evaluating all matched file pairs and writing the report to disk.
    def run_analysis(self):
        print("Starting analysis...")
        
        file_pairs = self.get_matching_files()
        
        if not file_pairs:
            print("No matching file pairs found!")
            return
        
        print(f"Found components: {len(file_pairs)}")
        
        all_metrics = []
        
        for key, files_list in file_pairs.items():
            file_info = files_list[0]
            print(f"\nAnalyzing: {key} | {file_info['timestamp']}")
            
            time_data = self.parse_time_file(file_info['time_file'])
            memory_data = self.parse_memory_file(file_info['memory_file'])
            
            print(f"  Found {len(time_data['operations'])} time operations")
            print(f"  Found {len(memory_data['operations'])} memory operations")
            
            metrics = self.calculate_metrics(time_data, memory_data, file_info)
            all_metrics.append(metrics)
        
        report = self.generate_report(all_metrics)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"analysis_{timestamp}.txt"
        output_path = os.path.join(self.analysis_dir, output_filename)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(report)
        
        print(f"\nAnalysis completed!")
        print(f"Report saved to: {output_path}")
        
        return output_path


if __name__ == "__main__":
    analyser = AnalyseTimeMemory()
    analyser.run_analysis()