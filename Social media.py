import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import re
import matplotlib.pyplot as plt
from collections import Counter

# Function to create the database and tables
def create_db():
    try:
        conn = sqlite3.connect('social_media_survey.db')
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # Create responses table
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                name TEXT NOT NULL,
                age TEXT NOT NULL,
                gender TEXT NOT NULL,
                platform TEXT NOT NULL,
                time_youtube TEXT,
                time_facebook TEXT,
                time_instagram TEXT,
                time_linkedin TEXT,
                most_active_time TEXT NOT NULL,
                devices TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Error creating database: {str(e)}")
    finally:
        conn.close()

# Function to validate email address
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to sign up a new user
def signup():
    signup_window = tk.Toplevel(root)
    signup_window.title("Sign Up")
    signup_window.geometry("400x300")
    signup_window.configure(bg="#f0f2f5")

    # Username
    tk.Label(signup_window, text="Username:", bg="#f0f2f5").pack(pady=(20, 5))
    signup_username = tk.Entry(signup_window, width=30)
    signup_username.pack(pady=5)

    # Password
    tk.Label(signup_window, text="Password:", bg="#f0f2f5").pack(pady=5)
    signup_password = tk.Entry(signup_window, show="*", width=30)
    signup_password.pack(pady=5)

    # Confirm Password
    tk.Label(signup_window, text="Confirm Password:", bg="#f0f2f5").pack(pady=5)
    confirm_password = tk.Entry(signup_window, show="*", width=30)
    confirm_password.pack(pady=5)

    def register():
        username = signup_username.get().strip()
        password = signup_password.get()
        confirm_pass = confirm_password.get()

        # Validate inputs
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        if password != confirm_pass:
            messagebox.showerror("Error", "Passwords do not match")
            return

        try:
            conn = sqlite3.connect('social_media_survey.db')
            cursor = conn.cursor()

            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                messagebox.showerror("Error", "Username already exists")
                return

            # Insert new user
            hashed_password = hash_password(password)
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                           (username, hashed_password))
            
            conn.commit()
            messagebox.showinfo("Success", "Account created successfully!")
            signup_window.destroy()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error creating account: {str(e)}")
        finally:
            conn.close()

    # Register Button
    register_button = tk.Button(signup_window, text="Register", command=register, 
                                bg="#1877f2", fg="white")
    register_button.pack(pady=20)

# Function to log in
def login():
    # Hide main window
    root.withdraw()

    # Create login window
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("400x300")
    login_window.configure(bg="#f0f2f5")

    # Username
    tk.Label(login_window, text="Username:", bg="#f0f2f5").pack(pady=(50, 5))
    login_username = tk.Entry(login_window, width=30)
    login_username.pack(pady=5)

    # Password
    tk.Label(login_window, text="Password:", bg="#f0f2f5").pack(pady=5)
    login_password = tk.Entry(login_window, show="*", width=30)
    login_password.pack(pady=5)

    def authenticate():
        username = login_username.get().strip()
        password = login_password.get()

        try:
            conn = sqlite3.connect('social_media_survey.db')
            cursor = conn.cursor()

            # Check credentials
            hashed_password = hash_password(password)
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                           (username, hashed_password))
            
            if cursor.fetchone():
                # Store logged-in username globally
                global current_user
                current_user = username
                
                # Close login window and show main survey window
                login_window.destroy()
                root.deiconify()
            else:
                messagebox.showerror("Error", "Invalid username or password")

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error logging in: {str(e)}")
        finally:
            conn.close()

    # Login Button
    login_button = tk.Button(login_window, text="Login", command=authenticate, 
                              bg="#1877f2", fg="white")
    login_button.pack(pady=20)

    # Sign Up Link
    signup_link = tk.Button(login_window, text="Create New Account", 
                             command=lambda: [signup(), login_window.destroy()], 
                             bg="#f0f2f5", fg="#1877f2", borderwidth=0)
    signup_link.pack(pady=10)

    # If login window is closed, exit the application
    login_window.protocol("WM_DELETE_WINDOW", root.quit)

# Function to clear form fields
def clear_form():
    name_entry.delete(0, tk.END)
    age_var.set("")
    gender_var.set("")
    platform_var.set("")
    youtube_time_var.set("")
    facebook_time_var.set("")
    instagram_time_var.set("")
    linkedin_time_var.set("")
    most_active_time_var.set("")
    devices_var.set("")
    email_entry.delete(0, tk.END)

# Function to submit form data to the database
def submit_form():
    name = name_entry.get().strip()
    email = email_entry.get().strip()
    age = age_var.get()
    gender = gender_var.get()
    platform = platform_var.get()
    youtube_time = youtube_time_var.get()
    facebook_time = facebook_time_var.get()
    instagram_time = instagram_time_var.get()
    linkedin_time = linkedin_time_var.get()
    most_active_time = most_active_time_var.get()
    devices = devices_var.get()

    # Validate inputs (same as before)
    if not all([name, email, age, gender, platform, most_active_time, devices]):
        messagebox.showerror("Error", "Please fill in all required fields")
        return

    if not validate_email(email):
        messagebox.showerror("Error", "Invalid email address")
        return

    try:
        conn = sqlite3.connect('social_media_survey.db')
        cursor = conn.cursor()

        # Insert survey response into the database with username
        cursor.execute('''
            INSERT INTO responses (username, name, email, age, gender, platform, 
            time_youtube, time_facebook, time_instagram, time_linkedin, 
            most_active_time, devices)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (current_user, name, email, age, gender, platform, 
              youtube_time, facebook_time, instagram_time, linkedin_time, 
              most_active_time, devices))

        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Survey submitted successfully!")
        clear_form()

    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Error submitting form: {str(e)}")

# Function to show graphs (modified to filter by current user)
def show_graphs():
    try:
        conn = sqlite3.connect('social_media_survey.db')
        cursor = conn.cursor()

        # Fetch responses for current user
        cursor.execute("SELECT platform, most_active_time, devices, age, gender FROM responses WHERE username = ?", (current_user,))
        data = cursor.fetchall()
        conn.close()

        if not data:
            messagebox.showerror("Error", "No data available to generate graphs!")
            return

        # Prepare data for plotting (same as before)
        platforms = [row[0] for row in data]
        active_times = [row[1] for row in data]
        devices = [row[2] for row in data]
        ages = [row[3] for row in data]
        genders = [row[4] for row in data]

        # Rest of the graph generation code remains the same as in the previous version
        plt.figure(figsize=(15, 10))

# Graph 1: Platform Distribution
        plt.subplot(2, 2, 1)
        platform_counts = Counter(platforms)
        plt.bar(platform_counts.keys(), platform_counts.values(), color="skyblue")
        plt.title("Most Used Social Media Platforms")
        plt.xlabel("Platform")
        plt.ylabel("Number of Users")
        plt.xticks(rotation=45)

        # Graph 2: Most Active Time
        plt.subplot(2, 2, 2)
        time_counts = Counter(active_times)
        plt.pie(time_counts.values(), labels=time_counts.keys(), autopct='%1.1f%%', startangle=140)
        plt.title("Most Active Time of Day")

        # Graph 3: Devices Used
        plt.subplot(2, 2, 3)
        device_counts = Counter(devices)
        plt.bar(device_counts.keys(), device_counts.values(), color="lightgreen")
        plt.title("Devices Used")
        plt.xlabel("Device")
        plt.ylabel("Number of Users")
        plt.xticks(rotation=45)

        # Graph 4: Age Distribution
        plt.subplot(2, 2, 4)
        age_counts = Counter(ages)
        plt.bar(age_counts.keys(), age_counts.values(), color="lightcoral")
        plt.title("Age Distribution")
        plt.xlabel("Age Group")
        plt.ylabel("Number of Users")
        plt.xticks(rotation=45)

        # Rest of the subplot generation remains the same
      

        plt.tight_layout()
        plt.show()
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Error fetching data: {str(e)}")

# Global variable to store current logged-in user
current_user = None

# Create the main Tkinter window
root = tk.Tk()
root.title("Social Media Usage Survey")
root.geometry("800x800")
root.configure(bg="#f0f2f5")

create_db()

# Survey form frame (same as before)
survey_frame = tk.Frame(root, bg="#f0f2f5")
survey_frame.pack(fill="both", expand=True, padx=40, pady=20)

# Title
tk.Label(survey_frame, text="Social Media Usage Survey",
         font=("Arial", 24, "bold"), bg="#f0f2f5", fg="#1877f2").pack(pady=(20, 10))

# Form container (same as before)
form_frame = tk.Frame(survey_frame, bg="white", padx=40, pady=40,
                      highlightthickness=1, highlightbackground="#dddfe2")
form_frame.pack(fill="x")

# Form fields
fields = [
    ("Name:", "name"),
    ("Email:", "email"),
    ("Age Group:", "age"),
    ("Gender:", "gender"),
    ("Most Used Platform:", "platform"),
    ("YouTube Usage Time:", "youtube_time"),
    ("Facebook Usage Time:", "facebook_time"),
    ("Instagram Usage Time:", "instagram_time"),
    ("LinkedIn Usage Time:", "linkedin_time"),
    ("Most Active Time:", "most_active_time"),
    ("Primary Device:", "devices")
]

# Variables for form fields
name_entry = tk.Entry(form_frame, width=30, font=("Arial", 12))
email_entry = tk.Entry(form_frame, width=30, font=("Arial", 12))

age_var = tk.StringVar()
age_combobox = ttk.Combobox(form_frame, textvariable=age_var,
                            values=["Under 18", "18-25", "25-30"],
                            state="readonly", width=28)

gender_var = tk.StringVar()
gender_combobox = ttk.Combobox(form_frame, textvariable=gender_var,
                               values=["Male", "Female"],
                               state="readonly", width=28)

platform_var = tk.StringVar()
platform_combobox = ttk.Combobox(form_frame, textvariable=platform_var,
                                 values=["YouTube", "Facebook", "Instagram", "LinkedIn"],
                                 state="readonly", width=28)

youtube_time_var = tk.StringVar()
youtube_time_combobox = ttk.Combobox(form_frame, textvariable=youtube_time_var,
                                     values=["Less than 1 hour", "1-3 hours", "3-5 hours", "More than 5 hours"],
                                     state="readonly", width=28)

facebook_time_var = tk.StringVar()
facebook_time_combobox = ttk.Combobox(form_frame, textvariable=facebook_time_var,
                                      values=["Less than 1 hour", "1-3 hours", "3-5 hours", "More than 5 hours"],
                                      state="readonly", width=28)

instagram_time_var = tk.StringVar()
instagram_time_combobox = ttk.Combobox(form_frame, textvariable=instagram_time_var,
                                       values=["Less than 1 hour", "1-3 hours", "3-5 hours", "More than 5 hours"],
                                       state="readonly", width=28)

linkedin_time_var = tk.StringVar()
linkedin_time_combobox = ttk.Combobox(form_frame, textvariable=linkedin_time_var,
                                      values=["Less than 1 hour", "1-3 hours", "3-5 hours", "More than 5 hours"],
                                      state="readonly", width=28)

most_active_time_var = tk.StringVar()
most_active_time_combobox = ttk.Combobox(form_frame, textvariable=most_active_time_var,
                                          values=["Morning", "Afternoon", "Evening", "Night"],
                                          state="readonly", width=28)

devices_var = tk.StringVar()
devices_combobox = ttk.Combobox(form_frame, textvariable=devices_var,
                                 values=["Mobile", "Laptop", "Desktop", "Tablet"],
                                 state="readonly", width=28)

# Packing form fields into the grid
fields_widgets = {
    "name": name_entry,
    "email": email_entry,
    "age": age_combobox,
    "gender": gender_combobox,
    "platform": platform_combobox,
    "youtube_time": youtube_time_combobox,
    "facebook_time": facebook_time_combobox,
    "instagram_time": instagram_time_combobox,
    "linkedin_time": linkedin_time_combobox,
    "most_active_time": most_active_time_combobox,
    "devices": devices_combobox
}

row = 0
for label, field in fields:
    tk.Label(form_frame, text=label, font=("Arial", 12), anchor="w", bg="white").grid(row=row, column=0, padx=5, pady=5)
    fields_widgets[field].grid(row=row, column=1, padx=5, pady=5)
    row += 1


# Submit and Show Graphs Buttons
submit_button = tk.Button(root, text="Submit Survey", font=("Arial", 16), 
                          bg="#1877f2", fg="white", command=submit_form)
submit_button.pack(pady=(10, 10), padx=40, fill="x")

show_graph_button = tk.Button(root, text="Show My Survey Graphs", font=("Arial", 16), 
                              bg="#1877f2", fg="white", command=show_graphs)
show_graph_button.pack(pady=(10, 10), padx=40, fill="x")

# Start with login screen
login()

root.mainloop()