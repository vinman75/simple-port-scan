import socket
import random
import ttkbootstrap as tb
from tkinter import scrolledtext, StringVar, messagebox
import threading
from concurrent.futures import ThreadPoolExecutor

class PortScannerApp:
    def __init__(self):
        self.setup_ui()
        self.scan_thread = None
        self.stop_scan = False

    def setup_ui(self):
        self.root = tb.Window(themename="darkly")
        self.root.title("Port Scanner")
        self.root.geometry("500x300")

        input_frame = tb.Frame(self.root)
        input_frame.pack(pady=10, fill='x')

        label = tb.Label(input_frame, text="IP/Domain:")
        label.pack(side='left', padx=5)

        self.entry_text = StringVar()
        self.entry = tb.Entry(input_frame, textvariable=self.entry_text, width=30)
        self.entry.pack(side='left', padx=5)

        self.scan_button = tb.Button(input_frame, text="Scan", command=self.start_scan, width=10)
        self.scan_button.pack(side='left', padx=5)

        self.stop_button = tb.Button(input_frame, text="Stop", command=self.stop_scan_method, state='disabled', width=10)
        self.stop_button.pack(side='left', padx=5)

        self.output = scrolledtext.ScrolledText(self.root, height=10)
        self.output.pack(expand=True, fill='both', padx=10, pady=10)

    def stop_scan_method(self):
        self.stop_scan = True
        self.stop_button.config(state='disabled')
    
    def tcp_port_scan(self, port, target_ip):
        if self.stop_scan:
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                self.output.insert('end', f"TCP Port {port} is open.\n")

    def udp_port_scan(self, port, target_ip):
        # A simple generic payload, not specific to any service
        generic_payload = b'hello'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.sendto(generic_payload, (target_ip, port))
            try:
                sock.recvfrom(1024)
                self.output.insert('end', f"UDP Port {port} is open or filtered.\n")
            except socket.timeout:
                # Just pass if there's no response, don't report it
                pass

    def start_scan(self):
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.output.delete('1.0', 'end')
        self.stop_scan = False

        target_domain = self.entry.get()
        self.scan_thread = threading.Thread(target=self.perform_scan, args=(target_domain,))
        self.scan_thread.start()

    def perform_scan(self, target_domain):
        try:
            target_ip = socket.gethostbyname(target_domain)
            self.output.insert('end', f"Scanning target: {target_ip}\n")

            port_list = list(range(1, 1025))
            random.shuffle(port_list)

            with ThreadPoolExecutor(max_workers=100) as executor:
                for port in port_list:
                    if self.stop_scan:
                        break
                    executor.submit(self.tcp_port_scan, port, target_ip)
                    executor.submit(self.udp_port_scan, port, target_ip)

            self.output.insert('end', "Scan completed.\n")
        except socket.gaierror as e:
            self.output.insert('end', f"Cannot resolve domain: {target_domain}. Error: {e}\n")
        finally:
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PortScannerApp()
    app.run()