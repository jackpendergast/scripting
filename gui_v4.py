import os, shutil, tkinter as tk
from time import strftime
from tkinter import filedialog, messagebox, scrolledtext
import yara

# Default rules (editable)
current_rules_source = r"""
rule DetectPowerShell {
    strings:
        $a = "powershell"
        $b = "curl"
        $c = "cmd.exe"
        $d = "wget"
        $e = "base64"
        $f = "net user"
        $g = "/wp-admin"
        $h = "/phpmyadmin"
        $i = ".env"
        $j = "' OR '1'='1" nocase
        $k = "--"
        $l = "&&"
        $m = "||"
        $n = "$("
    condition: any of them
}
"""
# Describe what each
identifier_lookup = {
	"$a": "Tries to Start powershell",
    "$b": "Outbound transfer via curl utility",
    "$c": "Launches windows command line",
    "$d": "Fetches files",
    "$e": "uses base64 (en/de)coding",
    "$f": "lists or edits local users",
    "$g": "Attempts wordpress admin panel",
    "$h": "Attempts phpMyAdmin panel",
    "$i": "Reads config file",
    "$j": "SQL test string",
    "$k": "SQL comment",
    "$l": "Shell command chain",
    "$m": "Shell command chain",
    "$n": "Shell command substitution"
}

#compile the rules at start-up, then re-compile them after edits
RULES = yara.compile(source=current_rules_source)

#   Define colors
BG , FG  = "#2B2B2B", "#00FF00"
FONT     = ("Courier New", 10)
CLR_BLUE = "#1E90FF"
CLR_GREEN="#28A745"
CLR_RED="#DC3545"
CLR_ORNG="#FFA500"

#  Gui Layout

root = tk.Tk()
root.title("YARA Folder Scanner (.txt files only)")
root.configure(bg=BG)
root.geometry("1100x720")   #set window size

folder_label = tk.Label(root, text="Folder: [None selected]", fg=FG, bg=BG, font=FONT) #default to none selected
folder_label.pack(anchor="w", padx=10, pady=(10, 5))

btn_frame = tk.Frame(root, bg=BG)#Define a container for the buttons
btn_frame.pack(fill="x", padx=10, pady=(0, 5))

#buttons
select_btn = tk.Button(
    btn_frame,
    text="Select Folder",
    font=FONT,
    fg="white",
    bg=CLR_BLUE,
    activebackground=FG
)
select_btn.pack(side="left", padx=5)

scan_btn = tk.Button(
    btn_frame,
    text="Scan",
    font=FONT,
    fg="white",
    bg=CLR_GREEN,
    activebackground=FG
)
scan_btn.pack(side="left", padx=5)

save_log_btn = tk.Button(
    btn_frame,
    text="Save Log",
    font=FONT,
    fg="white",
    bg=CLR_RED,
    activebackground=FG
)

edit_btn = tk.Button(
    btn_frame,
    text="Edit Rules",
    font=FONT,
    fg="white",
    bg=CLR_ORNG,
    activebackground=FG
)
edit_btn.pack(side="right", padx=5)

# Dialog box
text_area = scrolledtext.ScrolledText(
    root,
    width=120,
    height=24,
    fg=FG,
    bg=BG,
    insertbackground=FG,
    selectbackground="#005500",
    selectforeground="#FFFFFF",
    font=FONT
)
text_area.pack(fill="both", expand=True, padx=10, pady=10)
text_area.config(state="disabled")
text_area.tag_config("malfile", foreground=CLR_RED)

# Initialize these variables
matched_files = []
file_identifiers = {}
type_set = {}
total_indicators = 0

def log(msg, end="\n", tag=None):
    text_area.config(state="normal")
    text_area.insert(tk.END, msg+end, tag)
    text_area.see(tk.END)
    text_area.config(state="disabled")

#   Select the folder
def select_folder():
    folder = filedialog.askdirectory(title="Select Folder")
    if folder:
        folder_label.config(text=f"Folder: {folder}")
        text_area.config(state="normal")
        text_area.delete("1.0", tk.END)
        text_area.config(state="disabled")
        matched_files.clear()
        file_identifiers.clear()
        type_set.clear()
        if save_log_btn.winfo_ismapped():
            save_log_btn.pack_forget()

#   Edit the Rule list
def open_rule_editor():
    editor = tk.Toplevel(root)
    editor.title("YARA Rule Editor")
    editor.configure(bg=BG)
    editor.geometry("800x550")
    txt = scrolledtext.ScrolledText(
        editor,
        fg=FG,
        bg=BG,
        insertbackground=FG,
        font=FONT
    )
    txt.pack(fill="both", expand=True, padx=10, pady=(10,5))
    txt.insert("1.0", current_rules_source)

    # Function to exit the rules
    def save_rules():
        global RULES, current_rules_source
        src = txt.get("1.0", tk.END)
        try:
            RULES = yara.compile(source=src)
        except yara.SyntaxError as e:
            messagebox.showerror("YARA Syntax Error", str(e), parent=editor)
            return
        current_rules_source = src
        messagebox.showinfo("Rules Updated", "New rules compiled successfully.", parent=editor)
        editor.destroy()
    tk.Button(
        editor,
        text="Save & Re‑compile",
        fg="white",
        bg=CLR_ORNG,
        activebackground=FG,
        font=FONT,
        command=save_rules).pack(pady=(0,10)
    )

#   Export the log
def save_log_to_txt():
    data = text_area.get("1.0", tk.END).strip()
    if not data:
        messagebox.showwarning("No Log", "Log is empty.")
        return

    path = filedialog.asksaveasfilename(
        title="Save Log",
        defaultextension=".txt",
        filetypes=[("Text files","*.txt"),("All files","*.*")]
    )

    if not path:
        return

    try:
        open(path,"w",encoding="utf-8").write(data)
        messagebox.showinfo("Log Saved", path)
    except Exception as e:
        messagebox.showerror(f"Save Error: {str(e)}")

# Quarantine the files
def quarantine_files(parent):
    dest = filedialog.askdirectory(parent=parent, title="Select Quarantine Folder")
    if not dest:
        return
    errors=[]
    moved = 0

    for fp in matched_files:
        try:
            shutil.move(fp, dest)
            moved += 1
        except Exception as err:
            errors.append(f"{os.path.basename(fp)}: {err}")
    if errors:
        messagebox.showerror("Quarantine Errors", "\n".join(errors), parent=parent)
    else:
        messagebox.showinfo("Quarantined", f"{len(matched_files)} file(s) moved.")

# Define the summary window
def show_summary(total_files, match_count, start, end):
    win = tk.Toplevel(root)
    win.configure(bg=BG)
    win.title("Scan Summary")
    win.geometry("900x550")
    win.grab_set()
    win.transient(root)
    hdr = (f"Total .txt files scanned : {total_files}\n"
           f"Files with matches       : {match_count}\n"
           f"Total indicators matched : {total_indicators}\n"
           f"Scan started             : {start}\n"
           f"Scan finished            : {end}\n")

    tk.Label(
        win,
        text=hdr,
        fg=FG,
        bg=BG,
        font=FONT,
        justify="left"
    ).pack(anchor="w", padx=15, pady=(15,5))

    if match_count:
        box = scrolledtext.ScrolledText(
            win,
            height=12,
            fg=FG,
            bg=BG,
            font=FONT,
            wrap="word"
        )
        box.pack(fill="both", expand=True, padx=15, pady=(0,10))

        box.insert("1.0", "Suspicious files, identifiers, and patterns:\n" + "-" * 20 + "\n")
        for fn, ids in file_identifiers.items():
            box.insert(tk.END, f"\U0001F534{fn} -> {', '.join(sorted(ids))}\n")
            box.insert(tk.END, f"   Pattern -> {', '.join(sorted(type_set.get(fn, set())))}\n")
        box.config(state="disabled")
        tk.Button(
            win,
            text="Quarantine Detected Files",
            font=FONT,
            fg="white",
            bg=CLR_RED,
            activebackground=FG,
            command=lambda: quarantine_files(win)
        ).pack(pady=(0,10))

    tk.Button(
        win,
        text="Close",
        font=FONT,
        fg="white",
        bg=CLR_BLUE,
        command=win.destroy
    ).pack(pady=(0,15))

    if not save_log_btn.winfo_ismapped():
        save_log_btn.pack(side="left", padx=5)

# scan function
def scan_folder():
    global total_indicators
    folder = folder_label.cget("text")[8:]
    if folder in ("", "[None selected]"):
        messagebox.showwarning("No Folder","Please select a folder.")
        return
    matched_files.clear()
    file_identifiers.clear()
    type_set.clear()
    total_indicators=0

    text_area.config(state="normal")
    text_area.delete("1.0", tk.END)
    text_area.config(state="disabled")

    start = strftime("%Y-%m-%d %H:%M:%S")
    log(f"====== Scanning folder: {folder} ======\n")
    total_files = 0
    for rootdir,_,files in os.walk(folder):
        for file in files:
            if not file.lower().endswith(".txt"):
                continue
            total_files+=1
            folderPath=os.path.join(rootdir,file)
            try: matches=RULES.match(filepath=folderPath)
            except Exception as e:
                log(f"[Error] {file}: {e}")
                continue
            if matches:
                matched_files.append(folderPath)
                ids=file_identifiers.setdefault(file,set())
                types=type_set.setdefault(file,set())
                log("-" * 45)
                log("! Match\n")
                log("File       : ", end="")  # first half (default green)
                log(file, tag="malfile")
                for match in matches:
                    if not hasattr(match.strings[0],'identifier'):
                        items = match.strings
                    else:
                        items = []
                    for id in match.strings:
                        for instance in id.instances:
                            items.append((
                                instance.offset,
                                id.identifier,
                                instance.matched_data,
                                identifier_lookup.get(id.identifier, 'No Description')
                            ))
                    for off, ident, data, type in items:
                        ids.add(ident)
                        types.add(type)
                        total_indicators+=1

                        log(f"Identifier : {ident}")
                        log(f"Pattern    : {data.decode('utf-8', 'ignore')}")
                        log(f"Type       : {type}\n")

            else: log("-"*45+ f"\nNo matches in {file}")
    if not matched_files: log("\n=== No matches found ===")
    end = strftime("%Y-%m-%d %H:%M:%S")
    show_summary(total_files, len(matched_files), start, end)

# Bind the buttons
edit_btn.config   (command=open_rule_editor)
select_btn.config (command=select_folder)
scan_btn.config   (command=scan_folder)
save_log_btn.config(command=save_log_to_txt)

root.mainloop()