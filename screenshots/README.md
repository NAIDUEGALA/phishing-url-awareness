# Screenshots Directory

This directory stores actual image captures of your program execution and test results for submission.

Per academic and project integrity guidelines, **no fake screenshots are generated**. You can capture genuine output directly from your Windows 11 terminal.

## Required Screenshots

1. `sample_run.png` - Screenshot of `phishing_checker.py` running in Windows Terminal or PowerShell, demonstrating inspecting URLs.
2. `test_results.png` - Screenshot of running `python -m unittest discover -s tests -v` showing all 23 tests passing with `OK`.

## How to Capture Actual Screenshots on Windows 11

### Step-by-Step Instructions:

1. **Open Windows Terminal or PowerShell**:
   - Press `Win + X` and select **Terminal** (or search **PowerShell** in the Start menu).
   - Navigate to the project folder:
     ```powershell
     cd "c:\Users\Naidu E\Downloads\phishing url awareness checker\phishing-url-awareness"
     ```

2. **Capture `sample_run.png`**:
   - Run the application:
     ```powershell
     python phishing_checker.py
     ```
   - Enter one or two test URLs (for example, `http://192.0.2.10/account` and `https://www.example.com/login`).
   - Press **Windows Key + Shift + S** to open the Windows Snipping Tool.
   - Select the **Window Snip** or drag a rectangle across your terminal window.
   - Click the popup notification to open Snipping Tool, then click **Save** (`Ctrl + S`).
   - Save the file as:
     `c:\Users\Naidu E\Downloads\phishing url awareness checker\phishing-url-awareness\screenshots\sample_run.png`

3. **Capture `test_results.png`**:
   - In your terminal, run:
     ```powershell
     python -m unittest discover -s tests -v
     ```
   - Press **Windows Key + Shift + S**.
   - Capture the terminal window showing the test list and `OK` message.
   - Save the image as:
     `c:\Users\Naidu E\Downloads\phishing url awareness checker\phishing-url-awareness\screenshots\test_results.png`
