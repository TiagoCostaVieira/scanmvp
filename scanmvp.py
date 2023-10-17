import tkinter as tk
from tkinter import scrolledtext
import nmap
import subprocess

class SHELL():
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("shell")

        self.output_text = scrolledtext.ScrolledText(self.window, wrap=tk.WORD)
        self.output_text.pack(expand=True, fill='both')

        self.command_entry = tk.Entry(self.window)
        self.command_entry.pack(fill='x')
        self.command_entry.bind('<Return>', self.run_command)

        self.scan_button = tk.Button(self.window, text="Escanear Portas", command=self.scan_network)
        self.scan_button.pack()

    def run_command(self, event):
        self.command = self.command_entry.get()
        self.executar_comando(self.command)
        self.command_entry.delete(0, 'end')

    def executar_comando(self, command):
        self.output_text.insert('end', f"Executando comando: {command}\n")
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            self.output_text.insert('end', result)
        except subprocess.CalledProcessError as e:
            self.output_text.insert('end', "Erro: " + e.output)
        self.output_text.insert('end', '\n')
        self.output_text.see('end')

    def scan_network(self):
        self.output_text.insert('end', "Iniciando varredura da rede...\n")

        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.0.1/24', arguments='-p 22-80')

        for host in nm.all_hosts():
            self.output_text.insert('end', f"Host: {host}\n")
            for proto in nm[host].all_protocols():
                self.output_text.insert('end', f"Protocolo: {proto}\n")

                ports = nm[host][proto]
                for port in ports:
                    self.output_text.insert('end', f"Porta {port} ({ports[port]['name']}): {ports[port]['state']}\n")

        self.output_text.insert("'end', 'Varredura da rede concluída.\n'")
        self.output_text.see('end')

    def start(self):
        self.window.mainloop()

if __name__ == '__main__':
    terminal = SHELL()
    terminal.start()
