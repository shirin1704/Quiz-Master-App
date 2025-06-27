from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

IST = pytz.timezone('Asia/Kolkata')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirects users to login page if not logged in
login_manager.login_message_category = "info"

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    full_name = db.Column(db.String(150))
    dob = db.Column(db.String(150))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

# Subject Model
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    chapters = db.relationship('Chapter', backref='subject', cascade="all, delete", lazy=True)

# Chapter Model
class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    quizzes = db.relationship('Quiz', backref='chapter', cascade="all, delete", lazy=True)

# Quiz Model
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Quiz name
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    attempts = db.Column(db.Integer, default=0)  # Number of attempts
    highest_score = db.Column(db.Float, default=0)  # Highest score among attempts
    date_of_quiz = db.Column(db.String(50))
    deadline = db.Column(db.DateTime, nullable = False)
    max_score = db.Column(db.Integer, default = 0)
    questions = db.relationship('Question', backref='quiz', lazy=True)

# Question Model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_statement = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(150), nullable=False)
    option2 = db.Column(db.String(150), nullable=False)
    option3 = db.Column(db.String(150), nullable=False)
    option4 = db.Column(db.String(150), nullable=False)
    correct_option = db.Column(db.String(150), nullable=False)

# Scores Model
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_scored = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-Based Access Control
@app.before_request
def restrict_admin_routes():
    admin_routes = ['/admin/add_subject', '/admin/add_chapter/<int:subject_id>', '/admin/show_chapters/<int:subject_id>']
    if request.path.startswith('/admin') and (not current_user.is_authenticated or not current_user.is_admin):
        flash("Access denied! Admin privileges required.", "danger")
        return redirect(url_for('dashboard'))

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        full_name = request.form['full_name']
        dob = request.form['dob']
        user = User(username=username, password=password, full_name=full_name, dob=dob)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    username = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user:
            flash('User not found. Please register first!', 'danger')
            return redirect(url_for('login'))

        if check_password_hash(user.password, password):
            login_user(user, remember=True)  # Persist session

            # Redirect based on user type
            '''if user.is_admin:
                return redirect(url_for('dashboard'))  # Admin Dashboard
            else:
                return redirect(url_for('user_dashboard'))  # User Dashboard'''
            return redirect(url_for('dashboard'))

        flash('Incorrect password. Try again!', 'danger')

    return render_template('login.html', username = username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('dashboard'))  # Redirect admins to admin dashboard
    
    # Fetch quizzes user has taken
    quiz_attempts = Score.query.filter_by(user_id=current_user.id).all()
    subjects = Subject.query.all()

    return render_template('user_dashboard.html', subjects=subjects, quiz_attempts=quiz_attempts)

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"User Logged In: {current_user.username}, Admin: {current_user.is_admin}")

    if current_user.is_admin:
        # Fetch total stats
        total_subjects = Subject.query.count()
        total_quizzes = Quiz.query.count()
        total_users = User.query.filter_by(is_admin=False).count()

        # Fetch all quiz scores
        scores = db.session.query(Score.total_scored).all()
        scores = [score[0] for score in scores] 

        score_ranges = {
        "0-20%": 0,
        "21-40%": 0,
        "41-60%": 0,
        "61-80%": 0,
        "81-100%": 0}

        # Categorize scores into the defined ranges
        for score in scores:
            if score <= 20:
                score_ranges["0-20%"] += 1
            elif score <= 40:
                score_ranges["21-40%"] += 1
            elif score <= 60:
                score_ranges["41-60%"] += 1
            elif score <= 80:
                score_ranges["61-80%"] += 1
            else:
                score_ranges["81-100%"] += 1

        # Fetch all subjects
        subjects = Subject.query.all()

        return render_template('admin_dashboard.html', 
                            total_subjects=total_subjects, 
                            total_quizzes=total_quizzes, 
                            total_users=total_users, 
                            subjects=subjects, 
                            score_distribution=score_ranges)

    # If the user is not an admin, show only quizzes available to them
    else:
        subjects = Subject.query.all()  # Modify if users should see limited subjects
        #quiz_attempts = Score.query.filter_by(user_id=current_user.id).all()
        # Fetch total quizzes attempted
        #total_attempts = db.session.query(Score.quiz_id).filter(Score.user_id == current_user.id).distinct().count()
        user_scores = Score.query.filter_by(user_id=current_user.id).all()
        # Fetch average score
        total_attempts = len(set([score.quiz_id for score in user_scores]))  # Unique quizzes attempted
        average_score = round(sum([score.total_scored for score in user_scores]) / len(user_scores), 2) if user_scores else 0
        perfect_scores = sum(1 for score in user_scores if score.total_scored == 100)
        # Fetch 3 recommended quizzes (modify the logic if needed)
        recommended_quizzes = Quiz.query.order_by(db.func.random()).limit(3).all()

        # Fetch user quiz attempts along with the quiz name

        return render_template('user_dashboard.html', datetime = datetime,
                            total_attempts=total_attempts, average_score=average_score,
                            perfect_scores=perfect_scores, recommended_quizzes=recommended_quizzes)

@app.route('/get_score_distribution', methods=['GET'])
@login_required
def get_score_distribution():
    scores = db.session.query(Score.total_scored, db.func.count(Score.total_scored)).filter_by(user_id=current_user.id).group_by(Score.total_scored).all()
    score_data = {"scores": [s[0] for s in scores], "counts": [s[1] for s in scores]}
    return jsonify(score_data)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/admin_quizzes')
@login_required
def admin_quizzes():
    subjects = Subject.query.all()
    return render_template('show_admin_quizzes.html', subjects=subjects)

@app.route('/quizzes')
@login_required
def quizzes():
    subjects = Subject.query.all()

    # Fetch quizzes the user has taken
    from sqlalchemy.sql import func  
    from datetime import datetime

    quiz_attempts = db.session.query(
        Quiz.name.label("quiz_name"),
        Subject.name.label("subject_name"),
        Chapter.name.label("chapter_name"), 
        db.func.count(Score.id).label("attempts"),
        Quiz.highest_score.label("highest_score")
        ).join(Quiz, Quiz.id == Score.quiz_id)\
        .join(Chapter, Chapter.id == Quiz.chapter_id)\
        .join(Subject, Subject.id == Chapter.subject_id)\
        .filter(Score.user_id == current_user.id)\
        .group_by(Quiz.id, Subject.name, Chapter.name)\
        .all()
    
    current_time = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(IST)
    print(current_time)
    available_quizzes = Quiz.query.filter(Quiz.deadline > current_time).all()  # Active quizzes
    expired_quizzes = Quiz.query.filter(Quiz.deadline <= current_time).all()  # Expired quizzes

    return render_template('show_user_quizzes.html', quiz_attempts=quiz_attempts, subjects=subjects,
                           available_quizzes=available_quizzes, expired_quizzes=expired_quizzes)

@app.route('/view_quiz/<int:quiz_id>')
@login_required
def view_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('view_quiz.html', quiz=quiz, num_questions = len(quiz.questions))

# Admin functionalities
@app.route('/admin/add_subject', methods=['GET','POST'])
@login_required
def add_subject():
    if not current_user.is_admin or not hasattr(current_user, 'is_admin'):
        print("There is an issue")
        flash("Access denied! Only admins can add subjects.", "danger")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        print("no issue, adding subject")
        name = request.form['name']
        subject = Subject(name=name)
        db.session.add(subject)
        db.session.commit()
        flash("Subject added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_subject.html')

@app.route('/admin/delete_subject/<int:subject_id>', methods=['POST'])
@login_required
def delete_subject(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    subject = Subject.query.get(subject_id)
    if subject:
        # Deleting related chapters and quizzes
        chapters = Chapter.query.filter_by(subject_id=subject.id).all()
        for chapter in chapters:
            Quiz.query.filter_by(chapter_id=chapter.id).delete()
            db.session.delete(chapter)

        db.session.delete(subject)
        db.session.commit()
        flash('Subject and all related data deleted successfully!', 'success')
    else:
        flash('Subject not found!', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/admin/add_chapter/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def add_chapter(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    subject = Subject.query.get_or_404(subject_id)

    if request.method == 'POST':
        name = request.form['name']
        chapter = Chapter(name=name, subject_id=subject_id)
        db.session.add(chapter)
        db.session.commit()
        flash("Chapter added successfully!", "success")
        return redirect(url_for('show_chapters', subject_id = subject_id))
    
    return render_template('add_chapter.html', subject_id=subject_id, subject = subject)

@app.route('/admin/show_chapters/<int:subject_id>')
@login_required
def show_chapters(subject_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    subject = Subject.query.get(subject_id)
    if not subject:
        flash("Subject not found!", "danger")
        return redirect(url_for('dashboard'))

    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template('show_chapters.html', subject=subject, chapters=chapters)

@app.route('/admin/delete_chapter/<int:chapter_id>', methods=['POST'])
@login_required
def delete_chapter(chapter_id):
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    chapter = Chapter.query.get_or_404(chapter_id)
    
    # Delete all quizzes under this chapter first
    Quiz.query.filter_by(chapter_id=chapter_id).delete()
    
    # Now delete the chapter
    db.session.delete(chapter)
    db.session.commit()
    
    flash("Chapter and its quizzes deleted successfully!", "success")
    return redirect(url_for('show_chapters', subject_id=chapter.subject_id))

@app.route('/admin/add_question/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def add_question(quiz_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    if len(quiz.questions) >= 10:
        flash("Maximum limit of 10 questions reached for this quiz!", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        question_statement = request.form['question_statement']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_option = locals()[request.form['correct_option']]
        question = Question(
            quiz_id=quiz.id, question_statement=question_statement,
            option1=option1, option2=option2, option3=option3, option4=option4,
            correct_option=correct_option
        )
        db.session.add(question)

        quiz = Quiz.query.get_or_404(quiz_id)
        quiz.max_score = len(quiz.questions)

        db.session.commit()

        flash("Question added successfully!", "success")
        return redirect(url_for('add_question', quiz_id=quiz.id))
    
    return render_template('add_question.html', quiz=quiz)

# Fetch quiz questions API
@app.route('/quiz/<int:quiz_id>/questions', methods=['GET'])
def get_quiz_questions(quiz_id):
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return jsonify([{
        'id': q.id, 'question_statement': q.question_statement,
        'options': [q.option1, q.option2, q.option3, q.option4],
        'correct_option': q.correct_option
    } for q in questions])

@app.route('/take_quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if datetime.utcnow() > quiz.deadline:
        flash("The deadline for this quiz has passed. You cannot attempt it anymore.", "danger")
        return redirect(url_for('dashboard'))
    
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    # Process questions to send as a structured list
    processed_questions = []
    for question in questions:
        processed_questions.append({
            'id': question.id,
            'statement': question.question_statement,
            'options': [question.option1, question.option2, question.option3, question.option4],
        })

    return render_template('take_quiz.html', quiz=quiz, questions=processed_questions)

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    quiz_id = request.form['quiz_id']
    quiz = Quiz.query.get_or_404(quiz_id)

    if datetime.utcnow() > quiz.deadline:
        flash("You cannot submit this quiz because the deadline has passed.", "danger")
        return redirect(url_for('dashboard'))

    # Fetch all questions for the quiz
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    correct_count = 0
    total_questions = len(questions)
    total_score = 0
    user_answers = {}

    for question in questions:
        selected_answer = request.form.get(f'answers[{question.id}]')
        user_answers[question.id] = {
            "selected": selected_answer if selected_answer else "Not Answered",
            "correct": question.correct_option,
            "is_correct": selected_answer.strip() == question.correct_option.strip() if selected_answer else False
        }
        if selected_answer == question.correct_option:
            correct_count = correct_count + 1  # +1 for each correct answer

    # Calculate percentage score
    total_score = round((correct_count / total_questions) * 100, 2) if total_questions > 0 else 0

    # Store the score in the database
    score_entry = Score(user_id=current_user.id, quiz_id=quiz_id, total_scored=total_score)
    db.session.add(score_entry)

    # Update quiz attempts and highest score
    quiz.attempts += 1
    if quiz.highest_score is None or total_score > quiz.highest_score:
        quiz.highest_score = total_score

    db.session.commit()
    print(user_answers)
    return render_template('quiz_results.html', quiz=quiz, total_scored=total_score, questions=questions, user_answers=user_answers)

@app.route('/admin/add_quiz/<int:chapter_id>', methods=['GET', 'POST'])
@login_required
def add_quiz(chapter_id):
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    chapter = Chapter.query.get_or_404(chapter_id)

    if request.method == 'POST':
        name = request.form.get('name')
        date_of_quiz = request.form.get('date_of_quiz')
        deadline = request.form.get('deadline')

        if not name or not date_of_quiz or not deadline:
            flash("Fill in all the quiz details!", "danger")
            return redirect(url_for('add_quiz', chapter_id=chapter_id))

        try:
            deadline_dt = datetime.strptime(deadline, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Invalid deadline format!", "danger")
            return redirect(url_for('add_quiz', chapter_id=chapter_id))

        # Ensure the chapter does not have more than 10 quizzes
        if Quiz.query.filter_by(chapter_id=chapter_id).count() >= 10:
            flash("A chapter can have a maximum of 10 quizzes!", "warning")
            return redirect(url_for('show_quizzes', chapter_id=chapter_id))

        new_quiz = Quiz(name=name, chapter_id=chapter_id, date_of_quiz = date_of_quiz, deadline = deadline_dt)
        db.session.add(new_quiz)
        db.session.commit()

        flash("Quiz added successfully! Now let's add questions to it.", "success")
        return redirect(url_for('add_question', quiz_id=new_quiz.id))

    return render_template('add_quiz.html', chapter_id=chapter_id)

@app.route('/admin/show_quizzes/<int:chapter_id>')
@login_required
def show_quizzes(chapter_id):
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()

    quiz_data = []
    for quiz in quizzes:
        num_questions = len(quiz.questions)
        quiz_data.append({
            'id': quiz.id,
            'name': quiz.name,
            'attempts': quiz.attempts,
            'highest_score': quiz.highest_score,
            'date_of_quiz' : quiz.date_of_quiz,
            'deadline' : quiz.deadline,
            'num_questions': num_questions,  # Added count of questions
        })

    return render_template('show_quizzes.html', chapter=chapter, quizzes=quiz_data)

@app.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if not current_user.is_admin:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    quiz = Quiz.query.get_or_404(quiz_id)

    Question.query.filter_by(quiz_id=quiz_id).delete()

    db.session.delete(quiz)
    db.session.commit()
    
    flash("Quiz deleted successfully!", "success")
    return redirect(url_for('show_quizzes', chapter_id=quiz.chapter_id))

# Get Leaderboard Data
@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    scores = Score.query.order_by(Score.total_scored.desc()).limit(10).all()
    return jsonify([{'user': User.query.get(s.user_id).username, 'score': s.total_scored} for s in scores])

@app.route('/')
def home():
    return render_template('welcome.html')
    #return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.before_request
def ensure_fresh_login():
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        if not user:
            print("🔄 Session expired or user role changed. Logging out...")
            logout_user()
            return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure database tables are created
        
        # Check if an admin user exists; if not, create one
        existing_admin = User.query.filter_by(is_admin=True).first()
        if not existing_admin:
            admin_username = "admin@gmail.com"
            admin_password = generate_password_hash("Admin123", method="pbkdf2:sha256")
            admin_name = "Admin"
            admin_dob = "2004-04-17"
            admin = User(username=admin_username, password=admin_password, full_name=admin_name,dob=admin_dob,is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user exists")
        
    app.run(debug=True)