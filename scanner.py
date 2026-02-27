import psutil
import os
import platform
import tkinter as tk
from tkinter import ttk
from rich import print
import subprocess

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Connection Monitor")
        self.root.geometry("900x450")
        self.root.configure(bg="#f4f4f4")

        # Create Table Frame
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Create Table (Treeview)
        self.tree = ttk.Treeview(
            self.frame, 
            columns=("PID", "Process Name", "Status", "Local Address", "Remote Address", "Action"), 
            show="headings"
        )

        self.tree.heading("PID", text="PID")
        self.tree.heading("Process Name", text="Process Name")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Local Address", text="Local Address")
        self.tree.heading("Remote Address", text="Remote Address")
        self.tree.heading("Action", text="Action")

        self.tree.column("PID", width=50, anchor="center")
        self.tree.column("Process Name", width=150)
        self.tree.column("Status", width=100, anchor="center")
        self.tree.column("Local Address", width=150)
        self.tree.column("Remote Address", width=150)
        self.tree.column("Action", width=200, anchor="center")

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Refresh Button
        self.refresh_button = ttk.Button(self.root, text="Refresh", command=self.update_connections)
        self.refresh_button.pack(pady=10)

        # Initial Load
        self.update_connections()

    def get_network_processes(self):
        """Fetch only LISTEN & ESTABLISHED processes."""
        try:
            connections = psutil.net_connections(kind='inet')
            processes = []

            for conn in connections:
                if conn.status in ["LISTEN", "ESTABLISHED"]:
                    pid = conn.pid
                    if pid is not None:
                        try:
                            process = psutil.Process(pid)
                            name = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            name = "Unknown"

                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                        processes.append([pid, name, conn.status, laddr, raddr])

            return processes
        except Exception as e:
            print(f"[red]Error fetching network processes: {e}[/red]")
            return []

    def update_connections(self):
        """Update Table with Active Connections."""
        # Clear existing entries
        for row in self.tree.get_children():
            self.tree.delete(row)

        processes = self.get_network_processes()

        if not processes:
            print("[yellow]No active network processes found.[/yellow]")
            return

        for proc in processes:
            pid, name, status, laddr, raddr = proc
            row_id = self.tree.insert("", tk.END, values=(pid, name, status, laddr, raddr))

            # Create Block Button
            block_button = ttk.Button(self.tree, text="Block", command=lambda p=pid, l=laddr: self.block_process(p, l))
            allow_button = ttk.Button(self.tree, text="Allow", command=lambda l=laddr: self.allow_process(l))

            # Place buttons inside table
            self.tree.set(row_id, "Action", "🔴 Block / 🟢 Allow")

    def block_process(self, pid, local_address):
        """Block process by adding a firewall rule."""
        if platform.system() == "Windows":
            self.block_windows(local_address)
        else:
            self.block_ufw(local_address)

    def allow_process(self, local_address):
        """Allow process by removing firewall rule."""
        if platform.system() == "Windows":
            self.allow_windows(local_address)
        else:
            self.allow_ufw(local_address)

    def block_ufw(self, local_address):
        """Block a port using UFW on Linux/macOS."""
        try:
            port = local_address.split(":")[-1]
            if port.isdigit():
                command = f"sudo ufw deny {port}"
                subprocess.run(command, shell=True, check=True)
                print(f"[red]Blocked port {port} using UFW[/red]")
        except Exception as e:
            print(f"[yellow]Error blocking: {e}[/yellow]")

    def allow_ufw(self, local_address):
        """Allow a port using UFW on Linux/macOS."""
        try:
            port = local_address.split(":")[-1]
            if port.isdigit():
                command = f"sudo ufw allow {port}"
                subprocess.run(command, shell=True, check=True)
                print(f"[green]Allowed port {port} using UFW[/green]")
        except Exception as e:
            print(f"[yellow]Error allowing: {e}[/yellow]")

    def block_windows(self, local_address):
        """Block a port using Windows Firewall (Netsh)."""
        try:
            port = local_address.split(":")[-1]
            if port.isdigit():
                command = f"netsh advfirewall firewall add rule name=\"BlockPort{port}\" dir=in action=block protocol=TCP localport={port}"
                subprocess.run(command, shell=True, check=True)
                print(f"[red]Blocked port {port} using Windows Firewall[/red]")
        except Exception as e:
            print(f"[yellow]Error blocking: {e}[/yellow]")

    def allow_windows(self, local_address):
        """Allow a port using Windows Firewall (Netsh)."""
        try:
            port = local_address.split(":")[-1]
            if port.isdigit():
                command = f"netsh advfirewall firewall delete rule name=\"BlockPort{port}\" protocol=TCP localport={port}"
                subprocess.run(command, shell=True, check=True)
                print(f"[green]Allowed port {port} using Windows Firewall[/green]")
        except Exception as e:
            print(f"[yellow]Error allowing: {e}[/yellow]")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()
