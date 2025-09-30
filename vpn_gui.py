import tkinter as tk
from tkinter import ttk

class VPNGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VPN Client")
        self.root.geometry("400x450")
        self.root.resizable(False, False)
        self.root.configure(bg="#F5F6F5")  # Soft off-white background for a clean look

        # State variable for button style
        self.is_vpn_on = False

        # Configure styles for a professional color scheme
        style = ttk.Style()
        style.configure("Main.TFrame", background="#F5F6F5")
        style.configure("Clean.TLabel", background="#F5F6F5", font=("Helvetica", 10), foreground="#333333")  # Dark gray text
        style.configure("Analytics.TLabel", background="#F5F6F5", font=("Helvetica", 10, "italic"), foreground="#666666")  # Lighter gray for analytics
        style.configure("Toggle.TButton", font=("Helvetica", 12, "bold"), padding=10, background="#FFFFFF", foreground="#333333")  # White button with dark text
        style.map("Toggle.TButton", background=[("active", "#E0E0E0")])  # Light gray when clicked
        style.configure("Toggle.On.TButton", background="#FFFFFF", foreground="#333333", bordercolor="#FF6200", borderwidth=2)  # Orange border when on

        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="15", style="Main.TFrame")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Analytics placeholder
        self.analytics_frame = ttk.Frame(self.main_frame)
        self.analytics_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        self.analytics_label = ttk.Label(self.analytics_frame, text="Analytics: Not available", style="Analytics.TLabel")
        self.analytics_label.grid(row=0, column=0, sticky=tk.W)

        # Encryption version selection (placeholder)
        ttk.Label(self.main_frame, text="Encryption Version", style="Clean.TLabel").grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.version_var = tk.StringVar(value="RSA")
        versions = ["RSA", "QUIC", "X25519"]
        self.version_dropdown = ttk.Combobox(self.main_frame, textvariable=self.version_var, values=versions, state="readonly", width=25)
        self.version_dropdown.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))

        # Key directory input (placeholder)
        ttk.Label(self.main_frame, text="Key Directory", style="Clean.TLabel").grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
        self.key_dir_var = tk.StringVar(value="/path/to/keys")
        self.key_entry = ttk.Entry(self.main_frame, textvariable=self.key_dir_var, width=20)
        self.key_entry.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        ttk.Button(self.main_frame, text="Browse", command=self.browse_key_dir).grid(row=4, column=1, sticky=tk.W, pady=(0, 20))

        # On/Off toggle button with dynamic style
        self.toggle_button = ttk.Button(self.main_frame, text="On", command=self.toggle_vpn, style="Toggle.TButton")
        self.toggle_button.grid(row=5, column=0, columnspan=2, pady=20)

        # Status label (placeholder)
        self.status_var = tk.StringVar(value="Status: Disconnected")
        ttk.Label(self.main_frame, textvariable=self.status_var, style="Clean.TLabel").grid(row=6, column=0, columnspan=2, pady=(0, 10))

        # Log window (placeholder)
        self.log_text = tk.Text(self.main_frame, height=8, width=40, state="disabled", bg="#FFFFFF", relief="flat", borderwidth=1, foreground="#333333")
        self.log_text.grid(row=7, column=0, columnspan=2, pady=10)

    def browse_key_dir(self):
        """Placeholder for file dialog (no functionality yet)."""
        pass

    def toggle_vpn(self):
        """Toggle button style to simulate on/off state."""
        if not self.is_vpn_on:
            self.toggle_button.configure(style="Toggle.On.TButton")
            self.toggle_button.config(text="Off")
            self.is_vpn_on = True
        else:
            self.toggle_button.configure(style="Toggle.TButton")
            self.toggle_button.config(text="On")
            self.is_vpn_on = False

if __name__ == "__main__":
    root = tk.Tk()
    app = VPNGUI(root)
    root.mainloop()