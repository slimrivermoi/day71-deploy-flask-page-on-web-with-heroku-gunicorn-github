# day69-user-authetication-on-blog-for-blogowner-and-commentators
In this project, 3 tables are created (user_table, blog_posts, comments) in the same Database (posts.db) with different relationship, using **SQLAlchemy**.
 - user_table:blog_posts (parent:child, 1-to-many)
 - user_table:comments (parent:child, 1-to-many)
 - blog_posts: comments  (parent:child, 1-to-many)

The webforms are created and rendered with **WTForms and Jinja**. 
 - The registration will make user with id "1" as the Admin. The rest of other users will be as common users. 
 - As the Admin, you can create, edit or delete new post.
 - As common users, you can post comment on the post. 

The user authentication are completed with **Flask_Login_Manager and Decorator**
- the user can enter name, email address and password.
- If the email address does not exist, the user account will then be generated and stored in the database.
- The password will then been "hash and salted" (Level 4 authentication) before being stored in the DB.
- User who has not logged in cannot add any comment.
- Only Admin user can add, edit, delete post.

 Finally, the avatar of the users are being displayed with **Gravatar.**


|  | Description |
| ----------- | ----------- |
| Languages | Python, html, css |
| Python Libraries | Flask, SQLAlchemy, flask_login, werkzeug.security, Jinja, CKEditor, Gravatar |



How to run the file:
-
- Clone the repo and execute main.py.
- On your browser, copy and paste: http://127.0.0.1:5002.


Demo video
-


https://github.com/user-attachments/assets/d5511394-36cc-4017-baaf-8202d33560e0


