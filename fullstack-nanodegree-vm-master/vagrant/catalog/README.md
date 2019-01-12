Project Item Catalog by Nattaya Pikunkam

CONTENTS OF THIS FILE
---------------------
 * Introduction
 * Requirements Software
 * All files in project
 * How to run this project?


* Introduction
-----------------
An application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

- The homepage displays all current categories along with the latest added items.
- Selecting a specific category shows you all the items available for that category.
- Selecting a specific item shows you specific information of that item.
- After logging in, a user has the ability to add, update, or delete item info.
- The application provides a JSON endpoint.


* Requirements Software
--------------------------
- Vagrant and VirtualBox
- Python version 2.7.12

* All files in project
------------------------
- database_setup.py :  create the database
- database_info_initial.py : populate the database
- application.py : main file for run application
- client_secrets.json : file format for storing the client_id, client_secret, and other OAuth 2.0 parameters
- README.md : A read me file
- catalog.db : database of project
- templates(Folder)
    - add-category.html : for add category
    - add-item-cate.html : for add item in category that selected
    - add-item.html : for add item
    - delete-category.html : for delete category
    - delete-item.html : for delete item
    - edit-category.html : for edit category
    - edit-item.html : for edit item
    - index.html : main page
    - item.html : show detail of item in category that selected
    - items.html : show items in category that selected
    - login.html : google login
    - main.html : main page in header of all page
- static(Folder)
    - style.css : Style sheet

* How to run this project?
----------------------------
This project makes use on virtual machine (VM).

1. Use virtual machine (VM) 
    command for startup the virtual machine > $ vagrant up
    command for login in to virtual machine > $ vargrant ssh
    command for access my shared files > $ cd /vagrant

2. locate to in catalog directory 
    command for access to catalog directoty > $ cd catalog

3. Use command for show home page of project.
    command > $ python database_setup.py (to create the database)
    command > $ python database_info_initial.py (to populate the database)
    command > $ python application.py (navigate to localhost:8000 in your browser)

4. Use command for logout and shutdown vagrant VM.
    command for logout : Ctrl + D
    command for shutdown vagrant VM : $ vagrant halt