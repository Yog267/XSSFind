
# XSSFind

XSSFind is a tool designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications. It supports three modes of analysis: Static Analysis (SAST), Dynamic Analysis (DAST), and a Hybrid mode that combines both approaches.

## Features

- **Static Analysis (SAST):** Analyze source code for potential XSS vulnerabilities without executing the code.
- **Dynamic Analysis (DAST):** Test a running application (via a URL) for XSS vulnerabilities.
- **Hybrid Analysis:** Combines both SAST and DAST for comprehensive XSS vulnerability detection.
- **Real-time Progress Tracking:** Monitor the scan's progress in real-time through the web interface.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Yog267/XSSFind.git
   cd xssfind
   ```

2. **Create a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the Flask application:**
   ```bash
   python app.py
   ```

2. **Access XSSFind in your web browser:**
   Navigate to `http://localhost:5000` in your web browser.

3. **Select the desired analysis mode:**
   - **SAST:** Upload the source code of your application.
   - **DAST:** Enter the target URL of the running application.
   - **Hybrid:** Provide both the source code and the target URL.

4. **Start the scan:**
   - Click on the "Start Scan" button to begin the analysis.
   - Monitor the progress in real-time.

## Project Structure

- **app.py:** Main Flask application that handles routing and backend logic.
- **dast.py:** Contains logic for Dynamic Application Security Testing (DAST).
- **sast.py:** Handles Static Application Security Testing (SAST).
- **hybrid_tool.py:** Implements the hybrid analysis mode, combining SAST and DAST.
- **progress_tracker.py:** Tracks the progress of ongoing scans and updates the frontend.
- **templates/index.html:** HTML file that defines the user interface for XSSFind.
- **static/background.jpg:** Background image used in the web interface.

## Dependencies

XSSFind requires the following Python libraries, listed in `requirements.txt`:

- Flask
- Flask-SocketIO
- eventlet
- requests
- beautifulsoup4
- lxml
- selenium
- PyYAML
- Jinja2
- itsdangerous
- MarkupSafe

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or report issues in the repository.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgements

- [Flask](https://flask.palletsprojects.com/)
- [Selenium](https://www.selenium.dev/)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
