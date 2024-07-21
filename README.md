# BuySellHub
BuySellHub empower investors by providing a user-friendly platform through which they can buy and sell shares in leading companies like Google and Apple.
 - What does it do? 
   Example: "This is a web project which provides a user-friendly platform to purchase or sell shares.."
- What is the "new feature" which you have implemented that we haven't seen before?  
  Example: "reading from json file",  "sending values to the route to use it", "deleting from file" , "using jinja to display elemnts"


## Prerequisites
Did you add any additional modules that someone needs to install (for instance anything in Python that you `pip install-ed`)? 
List those here (if any).

Before running this project, ensure you have the following prerequisites installed:

- Python: Install Python from the official website: python.org
- Flask: You can install Flask using pip, Python's package installer. Run the following command:
` pip install Flask`
- Jinja: Jinja is a templating engine used by Flask, and it should be integrated into Visual Studio Code by default when you have the Python extension installed.
- Sqlite3 
`pip install sqlite3`
- Flask_session
`pip install flask_session`
- CS50 library, to control sqlite3
- Check sqlite cmd line `sqlite3 .\finance.db`
`pip install cs50`
- pytz
`pip install pytz`
- requests 
`pip install requests`
flask-change-password
- to run / to control flask `flask --app app.py run`
- 
## Project Checklist
- [x] It is available on GitHub.
- [x] It uses the Flask web framework.
- [x] It uses at least one module from the Python Standard Library other than the random module.
  Please provide the name of the module you are using in your app. 
  - Module name: datetime, re, os
  [x] It contains at least one class written by you that has both properties and methods. It uses `__init__()` to let the class initialize the object's attributes (note that  `__init__()` doesn't count as a method). This includes instantiating the class and using the methods in your app. Please provide below the file name and the line number(s) of at least one example of a class definition in your code as well as the names of two properties and two methods.
  - File name for the class definition: app.py
   Line number(s) for the class definition: line 31 in app.py.
    Name of two properties: username, password
  - Name of two methods: is_valid_username, is_valid_password
    - File name and line numbers where the methods are used: app.py in line 264 - 274
- [x] It makes use of JavaScript in the front end and uses the localStorage of the web browser.
- [x] It makes use of the reading and writing to the same file feature. in finance.db 
- [x] It contains conditional statements. Please provide below the file name and the line number(s) of at least
  one example of a conditional statement in your code.
  - File name:app.py, utility.py.
  - Line number(s): 37, 39, 44, 46, etc...
- [x] It contains loops. Please provide below the file name and the line number(s) of at least
  one example of a loop in your code.
  - File name: app.py, utility.py.
  - Line number(s):94, 99, 103, 318, .....
- [x] It lets the user enter a value in a text box at some point.
  This value is received and processed by your back end Python code.
- [x] It doesn't generate any error message even if the user enters a wrong input.
- [x] It is styled using CSS.
- [x] The code follows the code and style conventions as introduced in the course, is fully documented using comments and doesn't contain unused or experimental code. 
  In particular, the code should not use `print()` or `console.log()` for any information the app user should see. Instead, all user feedback needs to be visible in the browser.  
- [x] All exercises have been completed as per the requirements and pushed to the respective GitHub repository.
 
