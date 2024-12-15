import tkinter as tk
import time
from _thread import start_new_thread
import sys
from subprocess import getoutput
import json

def checkPath():
    if sys.platform != 'linux':
        None

    if 'not found' in getoutput('which rns'):
        return False

    return True

def makeReadOnlyBox(master, text, adjust=False):
    box = tk.Text(master, height=1, width=max(len(text), 25) if adjust else 25)

    box.insert(tk.END, text)
    box.configure(state=tk.DISABLED)

    return box

class HostLine(tk.Frame):
    def __init__(self, master, ip, name, mac, ports):
        super().__init__(master)

        tk.Label(
            self, text='IP:'
        ).grid(row=0, column=0)
        makeReadOnlyBox(self, ip).grid(row=0, column=1)

        tk.Label(
            self, text='Name:'
        ).grid(row=0, column=2)
        makeReadOnlyBox(self, name if name else '').grid(row=0, column=3)

        tk.Label (
            self, text='MAC:'
        ).grid(row=0, column=4)
        makeReadOnlyBox(self, mac if mac else '').grid(row=0, column=5)

        tk.Label(
            self, text='Ports:'
        ).grid(row=0, column=6)
        makeReadOnlyBox(self, ','.join(str(port) for port in ports), adjust=True).grid(row=0, column=7)

class Interface:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('rns gui')

        self.mainFrame = tk.Frame(self.root)
        self.currentView = None

        check = checkPath()
        if check is None:
            self.makeErrorWindow('rns GUI application only works in Linux')

        elif check == False:
            self.makeErrorWindow('`rns` executable is not in your PATH')

        else:
            self.make()

        self.mainFrame.pack(padx=10, pady=10, expand=True, fill='both')
        self.root.mainloop()

    def makeErrorWindow(self, text):
        self.root.title(self.root.title() + ' - error')
        tk.Label(
            self.mainFrame, text=text
        ).pack(padx=10, pady=10)

    def make(self):
        self.makeTopFrame()
        self.makeConstantsFrame()
        self.makeCommandFrame()

        self.runButton = tk.Button(self.mainFrame, text='run', command=self.run)
        self.runButton.pack(padx=10, pady=10)

        self.resultFrame = tk.Frame(self.mainFrame)
        self.resultFrame.pack(padx=10, pady=10)

        start_new_thread(self.commandUpdateLoop, ())

    def makeTopFrame(self):
        topFrame = tk.Frame(self.mainFrame)
        topFrame.pack(padx=10, pady=10)

        tk.Label(
            topFrame, text='Action: '
        ).pack(padx=5, pady=5, side=tk.LEFT)

        self.actionVar = tk.StringVar()
        self.actionVar.set('scan')

        self.actionEntry = tk.OptionMenu(topFrame, self.actionVar, *('scan', 'list'), command= lambda x: self.updateView(x))
        self.actionEntry.pack(padx=5, pady=5, side=tk.LEFT)

        self.actionFrame = tk.Frame(topFrame)
        self.actionFrame.pack(side=tk.LEFT)

        self.updateView('scan')

    def updateView(self, value):
        if value == self.currentView:
            return

        for child in self.actionFrame.winfo_children():
            child.destroy()

        self.currentView = value

        if value == 'scan':
            tk.Label(
                self.actionFrame, text='type: '
            ).pack(padx=5, pady=5, side=tk.LEFT)

            self.addressTypeVar = tk.StringVar()
            self.addressTypeVar.set('multiple')

            self.addressType = tk.OptionMenu(self.actionFrame, self.addressTypeVar, 'multiple', 'single', command=self.updateScanView)
            self.addressType.pack(padx=5, pady=5, side=tk.LEFT)

            tk.Label(
                self.actionFrame, text='IPv4'
            ).pack(padx=5, pady=5, side=tk.LEFT)

            self.ipV4Entry = tk.Entry(self.actionFrame)
            self.ipV4Entry.pack(padx=5, pady=5, side=tk.LEFT)

            tk.Label(
                self.actionFrame, text='mask: '
            ).pack(padx=5, pady=5, side=tk.LEFT)

            self.maskEntry = tk.Entry(self.actionFrame)
            self.maskEntry.pack(padx=5, pady=5, side=tk.LEFT)

            self.updateScanView('multiple')
            tk.Label(
                self.actionFrame, text='check: '
            ).pack(padx=5, pady=5, side=tk.LEFT)

            self.checkVar = tk.StringVar()
            self.checkVar.set('ports')

            self.checkEntry = tk.OptionMenu(self.actionFrame, self.checkVar, 'ports', 'mac-only', command=self.updateScanPorts)
            self.checkEntry.pack(padx=5, pady=5, side=tk.LEFT)

            self.scanPortsFrame = tk.Frame(self.actionFrame)
            self.scanPortsFrame.pack(padx=5, pady=5)

            self.updateScanPorts('ports')

        elif value == 'list':
            tk.Label(
                self.actionFrame, text='display: '
            ).pack(padx=5, pady=5, side=tk.LEFT)

            # ports [tcp | udp] | addresses | interfaces | routes | local
            self.listShowVar = tk.StringVar()
            self.listShowVar.set('ports')

            self.listShowEntry = tk.OptionMenu(
                self.actionFrame, self.listShowVar, 'ports', 'addresses', 'interfaces', 'routes', 'local',
                command=self.updatePortsType
            )
            self.listShowEntry.pack(padx=5, pady=5, side=tk.LEFT)

            self.portsTypeFrame = tk.Frame(self.actionFrame)
            self.portsTypeFrame.pack(padx=5, pady=5, side=tk.LEFT)

            self.updatePortsType('ports')

    def updateScanView(self, value):
        if value == 'multiple':
            self.maskEntry.configure(state='normal')
            self.maskEntry.delete('0', tk.END)

        else:
            self.maskEntry.delete('0', tk.END)
            self.maskEntry.insert(tk.END, 'no need')
            self.maskEntry.configure(state='disabled')

    def updatePortsType(self, value):
        for child in self.portsTypeFrame.winfo_children():
            child.destroy()

        if value == 'ports':
            tk.Label(
                self.portsTypeFrame, text='type: '
            ).pack(padx=5, pady=5, side=tk.LEFT)

            self.portsTypeVar = tk.StringVar()
            self.portsTypeVar.set('all')

            self.portsTypeEntry = tk.OptionMenu(self.portsTypeFrame, self.portsTypeVar, 'all', 'tcp', 'udp')
            self.portsTypeEntry.pack(padx=5, pady=5)

        else:
            self.portsTypeFrame.configure(width=0)
            self.portsTypeFrame.update()

    def updateScanPorts(self, value):
        for child in self.scanPortsFrame.winfo_children():
            child.destroy()

        if value == 'ports':
            self.scanPortsVar = tk.StringVar()
            self.scanPortsVar.set('std')

            self.scanPortsOptionEntry = tk.OptionMenu(
                self.scanPortsFrame, self.scanPortsVar, 'std', 'all', 'nmap', 'custom', command=self.toggleCustomPorts
            )
            self.scanPortsOptionEntry.pack(padx=5, pady=5, side=tk.LEFT)

    def toggleCustomPorts(self, value):
        if value == 'custom':
            self.customPortsEntry = tk.Entry(self.scanPortsFrame)
            self.customPortsEntry.pack(padx=5, pady=5, side=tk.LEFT)
        else:

            try:
                self.customPortsEntry.destroy()

            except:
                pass

    def makeConstantsFrame(self):
        constantsFrame = tk.Frame(self.mainFrame)
        constantsFrame.pack(padx=10, pady=10)

        self.scanMacVar = tk.BooleanVar()
        self.scanMacVar.set(False)

        self.scanMacFlag = tk.Checkbutton(constantsFrame, text='scan mac', variable=self.scanMacVar)
        self.scanMacFlag.pack(padx=5, pady=5, side=tk.LEFT)

        tk.Label(
            constantsFrame, text='host timeout'
        ).pack(padx=5, pady=5, side=tk.LEFT)

        self.hostTimeoutEntry = tk.Entry(constantsFrame)
        self.hostTimeoutEntry.pack(padx=5, pady=5, side=tk.LEFT)
        self.hostTimeoutEntry.insert(tk.END, '1000')

        tk.Label(
            constantsFrame, text='ports timeout'
        ).pack(padx=5, pady=5, side=tk.LEFT)

        self.portsTimeoutEntry = tk.Entry(constantsFrame)
        self.portsTimeoutEntry.pack(padx=5, pady=5, side=tk.LEFT)
        self.portsTimeoutEntry.insert(tk.END, '500')

    def makeCommandFrame(self):
        commandFrame = tk.Frame(self.mainFrame)
        commandFrame.pack(padx=10, pady=10)

        tk.Label(
            commandFrame, text='rns command:'
        ).pack(padx=10, pady=10, side=tk.LEFT)

        self.commandBox = tk.Text(commandFrame, height=1)
        self.commandBox.pack(padx=10, pady=10, side=tk.LEFT)
        self.commandBox.configure(state=tk.DISABLED)

    def commandUpdateLoop(self):
        current = None
        while True:
            command = self.makeCommand()

            if command != current:
                self.commandBox.configure(state=tk.NORMAL)
                self.commandBox.delete('0.0', tk.END)

                self.commandBox.insert(tk.END, command)
                self.commandBox.configure(state=tk.DISABLED)

                current = command

            time.sleep(0.1)

    def makeCommand(self):
        command = ['rns']

        action = self.actionVar.get()
        command.append(action)

        if action == 'scan':
            addressType = self.addressTypeVar.get()

            if addressType == 'single':
                command.append(addressType)

            command.append(self.ipV4Entry.get())

            mask = self.maskEntry.get()
            if mask != 'no need':
                command.append('mask')
                command.append(mask)

            check = self.checkVar.get()
            command.append(check)

            if check == 'ports':
                ports = self.scanPortsVar.get()

                if ports == 'custom':
                    command.append(self.customPortsEntry.get())

                else:
                    command.append(ports)

            if self.scanMacVar.get() and check != 'mac-only':
                command.append('scan-mac')

            if (hostTimeout := self.hostTimeoutEntry.get()) != '1000':
                command.append('host-timeout')
                command.append(hostTimeout)

            if (portsTimeout := self.portsTimeoutEntry.get()) != '500':
                command.append('ports-timeout')
                command.append(portsTimeout)

        elif action == 'list':
            show = self.listShowVar.get()
            command.append(show)

            if show == 'ports':
                portsType = self.portsTypeVar.get()
                command.append('' if portsType == 'all' else portsType)

        return ' '.join(command)

    def run(self):
        if sys.platform == 'linux':
            command = self.makeCommand()
            command += ' -j'

            jsonOutput = getoutput(command)
            self.resultFrame.destroy()

            if self.actionVar.get() == 'scan':
                res = json.loads(jsonOutput)

                self.resultFrame = tk.Frame(self.mainFrame)
                self.resultFrame.pack(padx=10, pady=10)

                for child in self.resultFrame.winfo_children():
                    child.destroy()

                for ip, info in res.items():
                    name = info.get('hostname')
                    mac = info.get('mac')
                    ports = info.get('ports')

                    HostLine(self.resultFrame, ip=ip, name=name, mac=mac, ports=ports).pack(padx=5, pady=5)

            else:
                self.resultFrame = tk.Text(self.mainFrame)
                self.resultFrame.pack(padx=10, pady=10)

                text = json.dumps(json.loads(jsonOutput), indent=4)
                self.resultFrame.insert(tk.END, text)

                self.resultFrame.configure(state=tk.DISABLED)

if __name__ == '__main__':
    Interface()