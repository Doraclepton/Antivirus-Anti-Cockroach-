from tkinter import *
import tkinter.messagebox as messagebox
import os
import re
import ast
import tokenize
from io import StringIO
import threading


class CodeAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'file_operations': [
                r'open\s*\([^)]*[\'\"](w|a|wb|ab)[\'\"][^)]*\)',
                r'os\.remove\s*\(',
                r'os\.unlink\s*\(',
                r'shutil\.rmtree\s*\(',
                r'os\.rmdir\s*\(',
                r'pathlib\.Path\.unlink\s*\(',
                r'pathlib\.Path\.rmdir\s*\(',
                r'subprocess\.run\s*\(\s*[\'\"](rm|del|erase)[\'\"]',
                r'__import__\s*\(\s*[\'\"]os[\'\"]\s*\)\.remove\s*\(',
            ],
            'system_commands': [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\(',
                r'subprocess\.Popen\s*\(',
                r'os\.popen\s*\(',
                r'exec\s*\(',
                r'eval\s*\(',
                r'compile\s*\(',
            ],
            'network_operations': [
                r'socket\.socket\s*\(',
                r'urllib\.request\.urlopen\s*\(',
                r'requests\.(get|post|put|delete)\s*\(',
                r'http\.client\.HTTPConnection\s*\(',
            ],
            'suspicious_functions': [
                r'__import__\s*\(',
                r'getattr\s*\(',
                r'setattr\s*\(',
                r'delattr\s*\(',
                r'hasattr\s*\(',
            ],
            'encryption_operations': [
                r'Crypto\.|cryptography\.|encrypt\s*\(|decrypt\s*\(',
            ]
        }

        self.system_paths = [
            'C:\\Windows\\', 'C:\\Program Files\\', 'C:\\Program Files (x86)\\',
            'C:\\System32\\', 'C:\\SysWOW64\\', 'C:\\$Recycle.Bin\\'
        ]

        self.system_extensions = {'.dll', '.sys', '.drv', '.exe', '.ocx', '.cpl'}

    def is_system_file(self, file_path):
        file_path_lower = file_path.lower()
        for system_path in self.system_paths:
            if file_path_lower.startswith(system_path.lower()):
                return True

        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension in self.system_extensions:
            return True

        return False

    def analyze_code_structure(self, content):
        try:
            tree = ast.parse(content)
            dangerous_calls = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'compile', '__import__']:
                            dangerous_calls.append(f"Вызов опасной функции: {func_name}")

                    elif isinstance(node.func, ast.Attribute):
                        attr_name = node.func.attr
                        if attr_name in ['system', 'popen', 'remove', 'rmdir', 'unlink']:
                            dangerous_calls.append(f"Вызов опасного метода: {attr_name}")

            return dangerous_calls
        except:
            return self.pattern_based_analysis(content)

    def pattern_based_analysis(self, content):
        suspicious_findings = []

        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    suspicious_findings.append(
                        f"{category}: {match.group(0)[:50]}..."
                    )

        return suspicious_findings

    def analyze_file_content(self, file_path, content):
        if self.is_system_file(file_path):
            return []

        suspicious_operations = self.analyze_code_structure(content)

        findings = []

        file_operation_patterns = [
            (r'(delete|remove|unlink)\s*\w*file', 'удаление файлов'),
            (r'(create|make|open.*w)\s*\w*file', 'создание файлов'),
            (r'(modify|edit|write)\s*\w*file', 'изменение файлов'),
            (r'(rename|move)\s*\w*file', 'переименование файлов'),
            (r'copy\s*\w*file', 'копирование файлов'),
        ]

        for pattern, operation in file_operation_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(operation)

        if suspicious_operations and not self.is_system_file(file_path):
            findings.extend(suspicious_operations)

        return findings


def scan_viruses():
    def scan_thread():
        messagebox.showinfo("Anti_Cockroach", "Сканирование начато")

        analyzer = CodeAnalyzer()

        scan_text.set("Начало сканирования...")
        file_count_var.set("Просканировано файлов: 0")
        suspicious_count_var.set("Найдено подозрительных файлов: 0")
        details_text.set("")

        file_count = 0
        suspicious_count = 0
        max_files = 9999999
        suspicious_files = []

        code_extensions = {
            '.py', '.txt', '.js', '.html', '.css', '.php', '.java', '.c', '.cpp',
            '.h', '.cs', '.vb', '.bat', '.ps1', '.sh', '.md', '.xml', '.json',
            '.yml', '.yaml', '.config', '.ini', '.log', '.rb', '.go', '.rs'
        }

        scan_details = []

        for root, dirs, files in os.walk('C:\\'):
            if file_count >= max_files:
                break

            for file in files:
                if file_count >= max_files:
                    break

                file_path = os.path.join(root, file)
                file_extension = os.path.splitext(file)[1].lower()

                scan_text.set(f"Сканируется: {os.path.basename(file_path)}")
                file_count_var.set(f"Просканировано файлов: {file_count + 1}")

                if file_count % 10 == 0:
                    w.update()

                if file_extension in code_extensions:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                            findings = analyzer.analyze_file_content(file_path, content)

                            if findings:
                                suspicious_count += 1
                                suspicious_files.append(file_path)
                                suspicious_count_var.set(f"Найдено подозрительных файлов: {suspicious_count}")

                                details = f"ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ: {file_path}\n"
                                details += "Обнаруженные операции:\n"
                                for finding in findings[:5]:
                                    details += f"  - {finding}\n"
                                details += "\n"

                                scan_details.append(details)

                                if len(scan_details) > 3:
                                    display_details = scan_details[-3:]
                                else:
                                    display_details = scan_details

                                details_text.set("\n".join(display_details))

                    except (IOError, PermissionError, UnicodeDecodeError, MemoryError):
                        pass

                file_count += 1

        file_count_var.set(f"Сканирование завершено! Всего файлов: {file_count}")
        scan_text.set("Сканирование завершено!")

        full_report = f"ПОЛНЫЙ ОТЧЕТ:\n"
        full_report += f"Просканировано файлов: {file_count}\n"
        full_report += f"Найдено подозрительных: {suspicious_count}\n\n"
        full_report += "ДЕТАЛИ:\n" + "\n".join(scan_details[-10:])

        details_text.set(full_report)

        messagebox.showinfo("Anti_Cockroach",
                            f"Сканирование завершено!\n"
                            f"Просканировано файлов: {file_count}\n"
                            f"Найдено подозрительных: {suspicious_count}")

    threading.Thread(target=scan_thread, daemon=True).start()


w = Tk()
w.title("Противотараканье средство")
w.resizable(True, True)
w.geometry("600x500")

scan_text = StringVar()
scan_text.set("Готов к сканированию...")

file_count_var = StringVar()
file_count_var.set("Готов к сканированию")

suspicious_count_var = StringVar()
suspicious_count_var.set("Найдено подозрительных файлов: 0")

details_text = StringVar()
details_text.set("Детали сканирования появятся здесь...")

a = Label(w, text="Здравствуйте! Вас приветствует антивирус", font=('Verdana', 10, 'italic'))
a.place(x=0, y=0, width=600, height=25)

b = Label(w, text="Anti_Cockroach", font=('Verdana', 10, 'bold'))
b.place(x=450, y=0, width=150, height=25)

details_frame = Frame(w)
details_frame.place(x=0, y=250, width=600, height=250)

details_label = Label(details_frame, textvariable=details_text, font=('Courier', 8),bg='black', fg='white', justify=LEFT, anchor='nw')
details_label.pack(fill=BOTH, expand=True)

suspicious_label = Label(w, textvariable=suspicious_count_var, font=('Verdana', 9),bg='lightcoral', relief='raised')
suspicious_label.place(x=0, y=200, width=600, height=25)

count_label = Label(w, textvariable=file_count_var, font=('Verdana', 9),bg='lightyellow', relief='raised')
count_label.place(x=0, y=225, width=600, height=25)

file_label = Label(w, textvariable=scan_text, font=('Verdana', 9),bg='white', relief='sunken')
file_label.place(x=0, y=30, width=600, height=25)

scan_button = Button(w, text="Начать сканирование", command=scan_viruses,font=('Verdana', 12, 'bold'), bg='lightgreen', fg='black')
scan_button.place(x=150, y=80, width=300, height=50)

w.mainloop()
