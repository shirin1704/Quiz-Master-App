# 🧠 QuizWhiz — Smart Quiz Management System

QuizWhiz is a full-stack web application built using **Flask** that allows admins to create and manage quizzes, while users can take quizzes, view results, and track performance.  
It’s designed to make learning and assessment engaging, efficient, and interactive.

---

## 🚀 Features

### 👩‍🏫 Admin Features
- Create, update, and delete **subjects**, **chapters**, and **quizzes**  
- Add up to **10 questions** per quiz  
- Manage quiz deadlines and availability  
- View **performance distribution graphs** and student quiz statistics

### 🎓 User Features
- Browse available quizzes by subject and chapter  
- Attempt quizzes within deadlines  
- Instantly view results and correct answers after submission  
- View previous scores and leaderboard rankings  

### 💡 Additional Features
- Flash messages and confirmation modals for user-friendly interaction  
- Quiz performance graph on the admin dashboard  
- Automatic deadline and expired quiz checks (IST time zone)  
- Clean, responsive UI using **Bootstrap 5**

---

## 🧩 Technologies Used

| Category | Technology |
|-----------|-------------|
| Backend | Flask (Python) |
| Frontend | HTML, CSS, Bootstrap, Jinja2 Templates |
| Database | SQLite (via Flask SQLAlchemy) |
| Visualization | Chart.js |
| Authentication | Flask-Login |
| Forms & Flash | Flask-WTF, Flask Messages |

### 🔍 Why These Technologies?
Flask provides a lightweight yet powerful backend framework.  
SQLAlchemy simplifies database interactions and schema management.  
Bootstrap and Chart.js make the interface responsive and visually appealing, while Flask-Login ensures secure access control.

---

## ⚙️ API Overview

The app includes REST endpoints for:
- Fetching quizzes, subjects, and chapters  
- Retrieving and posting quiz attempts  
- Fetching score distribution (for admin dashboards)  

---

## 🏅 Future Enhancements

Add quiz analytics dashboard for users
Implement email notifications for upcoming/expired quizzes
Add export/import functionality for quiz data
Integrate machine learning to recommend quizzes based on performance
