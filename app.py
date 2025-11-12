import sys
import re
from datetime import datetime
import bcrypt
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
# Firebase imports
import firebase_admin
from firebase_admin import credentials, firestore

# ==================== FLASK APP INIT ====================
app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, resources={r"/*": {"origins": "*"}})

# ==================== FIREBASE INITIALIZATION ====================
def initialize_firebase():
    """Initialize Firebase Admin SDK - looks for env var FIREBASE_KEY_FILE or falls back to bundled filenames."""
    # Try env var first, then a few sensible filenames
    candidates = []
    env_path = os.environ.get("FIREBASE_KEY_FILE")
    if env_path:
        candidates.append(env_path)

    # Prefer the "clean" filename uploaded (no double .json)
    candidates.extend([
        os.path.join(os.path.dirname(__file__), "huddle-c477f-firebase-adminsdk-fbsvc-a2d798bcc0.json"),
        os.path.join(os.path.dirname(__file__), "huddle-c477f-firebase-adminsdk-fbsvc-a2d798bcc0.json.json"),
        os.path.join(os.getcwd(), "huddle-c477f-firebase-adminsdk-fbsvc-a2d798bcc0.json"),
        os.path.join(os.getcwd(), "huddle-c477f-firebase-adminsdk-fbsvc-a2d798bcc0.json.json"),
    ])

    json_path = None
    for p in candidates:
        if p and os.path.exists(p):
            json_path = p
            break

    if not json_path:
        # Helpful error and exit
        print("❌ Firebase service account JSON not found. Tried these paths:")
        for c in candidates:
            print("   -", c)
        print("\nSet the FIREBASE_KEY_FILE environment variable to the full path of your service account JSON,")
        print("or place the JSON file in the project root with the expected name:")
        print("   huddle-c477f-firebase-adminsdk-fbsvc-a2d798bcc0.json")
        sys.exit(1)

    try:
        cred = credentials.Certificate(json_path)

        # Initialize only once
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)

        db = firestore.client()

        print("✅ Firebase initialized successfully!")
        try:
            project_id = firebase_admin.get_app().project_id
        except Exception:
            project_id = "huddle-c477f"
        print(f"   Project ID: {project_id}")
        print(f"   Service Account file: {json_path}")
        print("   Collections: users, groups, posts, questions, discussions\n")
        return db
    except Exception as e:
        print(f"❌ Firebase initialization failed: {e}")
        sys.exit(1)

# Initialize Firebase
db = initialize_firebase()

# Collection references
users_ref = db.collection('users')
groups_ref = db.collection('groups')
posts_ref = db.collection('posts')
questions_ref = db.collection('questions')
discussions_ref = db.collection('discussions')


def hash_password(password: str) -> str:
    """Hash password using bcrypt and return a UTF-8 string (safe for Firestore)."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # bcrypt output is ASCII-safe bytes; decode to str for storage
    return hashed.decode('utf-8')


def check_password(password: str, stored_hash: str) -> bool:
    """Check plaintext password against stored hash (stored_hash is string)."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception:
        return False


def _get_doc_id_from_add_result(add_result):
    """
    Firestore .add() may return a tuple. Try to extract DocumentReference.id robustly.
    """
    try:
        # If tuple/list: find first element that has .id
        if isinstance(add_result, (list, tuple)):
            for part in add_result:
                if hasattr(part, "id"):
                    return part.id
            # fallback: first element id if present
            first = add_result[0]
            return getattr(first, "id", None)
        # If a DocumentReference
        if hasattr(add_result, "id"):
            return add_result.id
    except Exception:
        pass
    return None


# ==================== HTML PAGE ROUTES ====================

@app.route('/')
def index():
    return send_from_directory('.', 'frontpage.html')


@app.route('/<path:filename>')
def serve_file(filename):
    """Serve any static file from project root."""
    return send_from_directory('.', filename)


# ==================== USER AUTHENTICATION ROUTES ====================

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        fullName = data.get('fullName')
        university = data.get('university')
        branch = data.get('branch')
        academicYear = data.get('academicYear')
        skills = data.get('skills', [])

        if not (email and password and fullName and university and branch and academicYear):
            return jsonify({'error': 'All fields except skills are required'}), 400

        # Check if user exists
        existing_users = users_ref.where('email', '==', email).limit(1).get()
        if len(list(existing_users)) > 0:
            return jsonify({'error': 'User already exists'}), 409

        pw_hash = hash_password(password)

        user_data = {
            'email': email,
            'password': pw_hash,  # stored as string
            'fullName': fullName,
            'university': university,
            'branch': branch,
            'academicYear': academicYear,
            'skills': skills,
            'profilePhotoUrl': '',
            'coverPhotoUrl': '',
            'bio': 'Passionate student focused on learning and building innovative projects.',
            'createdAt': firestore.SERVER_TIMESTAMP
        }

        # Add user to Firestore
        add_res = users_ref.add(user_data)
        user_id = _get_doc_id_from_add_result(add_res) or ""

        print(f"✅ User created: {email} | ID: {user_id}")

        return jsonify({
            'success': True,
            'message': 'Account created successfully!',
            'user': {
                'id': user_id,
                'email': email,
                'fullName': fullName,
                'university': university,
                'branch': branch,
                'academicYear': academicYear,
                'skills': skills,
                'profilePhotoUrl': '',
                'coverPhotoUrl': '',
                'bio': user_data['bio']
            }
        }), 200
    except Exception as e:
        print(f"❌ Signup error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to create account', 'details': str(e)}), 500


@app.route("/login", methods=["POST"])
def login_api():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        # Query user by email
        users = users_ref.where('email', '==', email).limit(1).get()
        users_list = list(users)

        if len(users_list) == 0:
            return jsonify({'error': 'User not found'}), 404

        user_doc = users_list[0]
        user = user_doc.to_dict()
        user_id = user_doc.id

        stored_pw = user.get('password', '')
        if not check_password(password, stored_pw):
            return jsonify({'error': 'Incorrect password'}), 401

        user_data = {
            "id": user_id,
            "email": user['email'],
            "fullName": user.get('fullName', ''),
            "university": user.get('university', ''),
            "branch": user.get('branch', ''),
            "academicYear": user.get('academicYear', ''),
            "skills": user.get('skills', []),
            "profilePhotoUrl": user.get('profilePhotoUrl', ''),
            "coverPhotoUrl": user.get('coverPhotoUrl', ''),
            "bio": user.get('bio', '')
        }

        print(f"✅ User logged in: {email}")
        return jsonify({'success': True, 'user': user_data}), 200
    except Exception as e:
        print(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500


# ==================== USER PROFILE ROUTES ====================

@app.route("/updateprofile", methods=["POST"])
def update_profile():
    try:
        data = request.get_json()
        user_id = data.get("userId")

        if not user_id:
            return jsonify({"error": "User ID required"}), 400

        update_data = {}
        for field in ['fullName', 'bio', 'profilePhotoUrl', 'coverPhotoUrl', 'skills']:
            if field in data:
                update_data[field] = data[field]

        # Update user document
        users_ref.document(user_id).update(update_data)

        print(f"✅ Profile updated: {user_id}")
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"❌ Update profile error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to update", "details": str(e)}), 500


@app.route("/getuser/<user_id>", methods=["GET"])
def get_user(user_id):
    try:
        print(f"🔍 Fetching user: {user_id}")

        # Get user document
        user_doc = users_ref.document(user_id).get()

        if not user_doc.exists:
            print(f"❌ User not found: {user_id}")
            return jsonify({"success": False, "error": "User not found"}), 404

        user = user_doc.to_dict()
        user_data = {
            "id": user_doc.id,
            "email": user.get('email', ''),
            "fullName": user.get('fullName', ''),
            "university": user.get('university', ''),
            "branch": user.get('branch', ''),
            "academicYear": user.get('academicYear', ''),
            "skills": user.get('skills', []),
            "profilePhotoUrl": user.get('profilePhotoUrl', ''),
            "coverPhotoUrl": user.get('coverPhotoUrl', ''),
            "bio": user.get('bio', '')
        }

        print(f"✅ Retrieved user: {user_data['fullName']} (ID: {user_data['id']})")
        return jsonify({"success": True, "user": user_data}), 200
    except Exception as e:
        print(f"❌ Get user error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Failed to get user: {str(e)}"}), 500


# ==================== GROUP ROUTES ====================

@app.route('/getavailablegroups', methods=['GET', 'POST'])
def get_groups():
    try:
        if request.method == 'POST' and request.json:
            data = request.get_json()
            userid = str(data.get('userId', ''))
        else:
            userid = str(request.args.get('userId', ''))

        # Get all groups
        groups = groups_ref.order_by('createdAt', direction=firestore.Query.DESCENDING).stream()
        groupslist = []

        for group_doc in groups:
            group = group_doc.to_dict()
            group_id = group_doc.id

            members = group.get('members', [])
            members = [str(m) for m in members]
            preferredteamsize = group.get('preferred_team_size') or group.get('preferred_team_size') or group.get('preferred_team_size')  # keep compatibility
            maxsize = None

            if preferredteamsize:
                match = re.search(r'(\d+)', str(preferredteamsize))
                if match:
                    maxsize = int(match.group(1))
                else:
                    try:
                        maxsize = int(preferredteamsize)
                    except:
                        maxsize = None

            isfull = False
            if maxsize and len(members) >= maxsize:
                isfull = True

            ismember = userid in members if userid else False
            projectname = group.get('project_name')
            if not projectname or not str(projectname).strip():
                projectname = "Unnamed Group"

            groupslist.append({
                "groupId": group_id,
                "creatoruserid": str(group.get('creatoruserid')),
                "members": members,
                "memberCount": len(members),
                "maxMembers": maxsize,
                "isFull": isfull,
                "isMember": ismember,
                "preferredteamsize": preferredteamsize,
                "projectname": projectname,
                "descriptionobjective": group.get('description_objective', ""),
                "projecttimeline": group.get('project_timeline', ""),
                "requiredskills": group.get('required_skills', []),
                "createdAt": group.get('createdAt').isoformat() if group.get('createdAt') else datetime.utcnow().isoformat()
            })

        return jsonify(success=True, groups=groupslist), 200
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(error="Could not load groups", details=str(e)), 500


@app.route("/creategroup", methods=["POST"])
def create_group():
    try:
        data = request.get_json()

        if not data.get("project_name"):
            return jsonify({"error": "Project name required"}), 400

        creator_id = str(data.get("creatoruserid"))

        group_data = {
            "creatoruserid": creator_id,
            "project_name": data.get("project_name"),
            "description_objective": data.get("description_objective", ""),
            "preferred_team_size": data.get("preferred_team_size", ""),
            "required_skills": data.get("required_skills", []),
            "project_timeline": data.get("project_timeline", ""),
            "members": [creator_id],
            "createdAt": firestore.SERVER_TIMESTAMP
        }

        # Add group to Firestore
        add_res = groups_ref.add(group_data)
        group_id = _get_doc_id_from_add_result(add_res) or ""

        print(f"✅ Group created: {group_data['project_name']} | ID: {group_id}")

        return jsonify({
            "success": True,
            "message": "Group created successfully!",
            "groupId": group_id
        }), 200
    except Exception as e:
        print(f"❌ Create group error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to create group", "details": str(e)}), 500


@app.route("/joingroup", methods=["POST"])
def join_group_api():
    try:
        data = request.get_json()
        user_id = str(data.get("user_id"))
        group_id = data.get("group_id")

        if not user_id or not group_id:
            return jsonify({"error": "User ID and Group ID required"}), 400

        print(f"🔍 Join group - User: {user_id}, Group: {group_id}")

        # Get group document
        group_doc = groups_ref.document(group_id).get()

        if not group_doc.exists:
            print(f"❌ Group not found: {group_id}")
            return jsonify({"error": "Group not found"}), 404

        # Add user to members array
        groups_ref.document(group_id).update({
            'members': firestore.ArrayUnion([str(user_id)])
        })

        print(f"✅ User {user_id} joined group {group_id}")
        return jsonify({"success": True, "message": "Joined successfully!"}), 200
    except Exception as e:
        print(f"❌ Join group error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to join group: {str(e)}"}), 500


@app.route("/leavegroup", methods=["POST"])
def leave_group_api():
    try:
        data = request.get_json()
        user_id = str(data.get("user_id"))
        group_id = data.get("group_id")

        if not user_id or not group_id:
            return jsonify({"error": "User ID and Group ID required"}), 400

        print(f"🔍 Leave group - User: {user_id}, Group: {group_id}")

        # Get group document
        group_doc = groups_ref.document(group_id).get()

        if not group_doc.exists:
            return jsonify({"error": "Group not found"}), 404

        # Remove user from members array
        groups_ref.document(group_id).update({
            'members': firestore.ArrayRemove([str(user_id)])
        })

        print(f"✅ User {user_id} left group {group_id}")
        return jsonify({"success": True, "message": "Left group successfully!"}), 200
    except Exception as e:
        print(f"❌ Leave group error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to leave group: {str(e)}"}), 500


@app.route("/getmygroups", methods=["GET"])
def get_my_groups():
    try:
        user_id = str(request.args.get('userId'))
        if not user_id or user_id == 'None':
            return jsonify({"error": "User ID required"}), 400

        # Query groups where user is a member
        my_groups = groups_ref.where('members', 'array_contains', user_id).stream()

        groups_list = []
        for group_doc in my_groups:
            group = group_doc.to_dict()
            groups_list.append({
                "groupId": group_doc.id,
                "groupName": group.get("project_name", "Unnamed Group")
            })

        print(f"✅ Retrieved {len(groups_list)} groups for user {user_id}")
        return jsonify({"success": True, "groups": groups_list}), 200

    except Exception as e:
        print(f"❌ Get my groups error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Could not load user's groups", "details": str(e)}), 500


# ==================== POST ROUTES ====================

@app.route("/createpost", methods=["POST"])
def create_post():
    try:
        data = request.get_json()

        post_data = {
            "userId": data.get("userId"),
            "userName": data.get("userName"),
            "userPhoto": data.get("userPhoto", ""),
            "content": data.get("content", ""),
            "imageUrl": data.get("imageUrl", ""),
            "likes": [],
            "comments": [],
            "createdAt": firestore.SERVER_TIMESTAMP
        }

        # Add post to Firestore
        add_res = posts_ref.add(post_data)
        post_id = _get_doc_id_from_add_result(add_res) or ""

        print(f"✅ Post created by: {post_data['userName']} | ID: {post_id}")

        return jsonify({
            "success": True,
            "message": "Post created successfully!",
            "postId": post_id
        }), 200
    except Exception as e:
        print(f"❌ Create post error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to create post", "details": str(e)}), 500


@app.route("/getposts", methods=["GET"])
def get_posts():
    try:
        # Get posts ordered by creation date
        posts = posts_ref.order_by('createdAt', direction=firestore.Query.DESCENDING).limit(50).stream()

        posts_list = []
        for post_doc in posts:
            post = post_doc.to_dict()
            posts_list.append({
                "postId": post_doc.id,
                "userId": post.get("userId"),
                "userName": post.get("userName"),
                "userPhoto": post.get("userPhoto", ""),
                "content": post.get("content", ""),
                "imageUrl": post.get("imageUrl", ""),
                "likes": post.get("likes", []),
                "comments": post.get("comments", []),
                "createdAt": post.get("createdAt").isoformat() if post.get("createdAt") else datetime.utcnow().isoformat()
            })

        print(f"✅ Retrieved {len(posts_list)} posts")
        return jsonify({"success": True, "posts": posts_list}), 200
    except Exception as e:
        print(f"❌ Get posts error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Could not load posts", "details": str(e)}), 500


# ==================== Q&A ROUTES ====================

@app.route("/createquestion", methods=["POST"])
def create_question():
    try:
        data = request.get_json()

        if not data.get("title") or len(data.get("title", "").strip()) < 10:
            return jsonify({"error": "Question title must be at least 10 characters"}), 400

        question_data = {
            "userId": str(data.get("userId")),
            "userName": data.get("userName"),
            "userPhoto": data.get("userPhoto", ""),
            "title": data.get("title").strip(),
            "content": data.get("content", "").strip(),
            "tags": data.get("tags", []),
            "answers": [],
            "votes": 0,
            "views": 0,
            "createdAt": firestore.SERVER_TIMESTAMP
        }

        # Add question to Firestore
        add_res = questions_ref.add(question_data)
        question_id = _get_doc_id_from_add_result(add_res) or ""

        print(f"✅ Question created: {question_data['title'][:50]}... | ID: {question_id}")

        return jsonify({
            "success": True,
            "message": "Question posted successfully!",
            "questionId": question_id
        }), 200
    except Exception as e:
        print(f"❌ Create question error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to create question: {str(e)}"}), 500


@app.route("/getquestions", methods=["GET"])
def get_questions():
    try:
        filter_type = request.args.get('filter', 'all').lower()
        search = request.args.get('search', '').strip()
        page = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 5))))
        skip = (page - 1) * limit

        print(f"🔥 GET /getquestions - filter: {filter_type}, search: '{search}', page: {page}, limit: {limit}")

        # Build query
        query = questions_ref

        # Apply search (Firestore has limited text search capabilities)
        if search:
            search_term = search.replace('#', '').strip().lower()
            # This is a simple tags array_contains search - requires tags to be stored lowercased
            query = query.where('tags', 'array_contains', search_term)

        # Apply filter
        if filter_type == 'most-voted':
            query = query.order_by('votes', direction=firestore.Query.DESCENDING)
        else:  # 'recent' or 'all'
            query = query.order_by('createdAt', direction=firestore.Query.DESCENDING)

        # Get all matching questions for count (careful on very large collections)
        all_questions = list(query.stream())
        total_count = len(all_questions)

        # Apply pagination
        paginated_questions = all_questions[skip:skip + limit]

        print(f"📊 Found {total_count} questions matching criteria, returning {len(paginated_questions)} for page {page}")

        # Format response
        questions_list = []
        for q_doc in paginated_questions:
            q = q_doc.to_dict()

            # Ensure answers have all required fields
            formatted_answers = []
            for idx, answer in enumerate(q.get('answers', [])):
                formatted_answer = {
                    'answerId': answer.get('answerId', q_doc.id + '_ans_' + str(idx)),
                    'userId': str(answer.get('userId', '')),
                    'userName': answer.get('userName', 'Anonymous'),
                    'userPhoto': answer.get('userPhoto', ''),
                    'content': answer.get('content', ''),
                    'votes': int(answer.get('votes', 0)),
                    'accepted': bool(answer.get('accepted', False)),
                    'createdAt': answer.get('createdAt', datetime.utcnow().isoformat())
                }
                formatted_answers.append(formatted_answer)

            questions_list.append({
                "questionId": q_doc.id,
                "userId": str(q.get("userId", '')),
                "userName": q.get("userName", 'Anonymous'),
                "userPhoto": q.get("userPhoto", ""),
                "title": q.get("title", "Untitled Question"),
                "content": q.get("content", ""),
                "tags": q.get("tags", []),
                "answers": formatted_answers,
                "votes": int(q.get("votes", 0)),
                "views": int(q.get("views", 0)),
                "createdAt": q.get("createdAt").isoformat() if q.get("createdAt") else datetime.utcnow().isoformat()
            })

        total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1

        print(f"✅ Retrieved {len(questions_list)} questions (Page {page}/{total_pages})")

        return jsonify({
            "success": True,
            "questions": questions_list,
            "pagination": {
                "currentPage": page,
                "totalPages": total_pages,
                "totalItems": total_count,
                "itemsPerPage": limit
            }
        }), 200

    except Exception as e:
        print(f"❌ Get questions error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": f"Could not load questions: {str(e)}"}), 500


@app.route("/addanswer", methods=["POST"])
def add_answer():
    try:
        data = request.get_json()
        question_id = data.get("questionId")
        content = data.get("content", "").strip()

        if not question_id:
            return jsonify({"error": "Question ID required"}), 400

        if not content or len(content) < 5:
            return jsonify({"error": "Answer must be at least 5 characters"}), 400

        answer = {
            "answerId": f"{question_id}_ans_{int(datetime.utcnow().timestamp())}",
            "userId": str(data.get("userId")),
            "userName": data.get("userName", "Anonymous"),
            "userPhoto": data.get("userPhoto", ""),
            "content": content,
            "votes": 0,
            "accepted": False,
            "createdAt": datetime.utcnow().isoformat()
        }

        # Add answer to question's answers array
        questions_ref.document(question_id).update({
            'answers': firestore.ArrayUnion([answer])
        })

        print(f"✅ Answer added to question {question_id}")
        return jsonify({"success": True, "message": "Answer posted!"}), 200
    except Exception as e:
        print(f"❌ Add answer error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to add answer: {str(e)}"}), 500


@app.route("/votequestion", methods=["POST"])
def vote_question():
    try:
        data = request.get_json()
        question_id = data.get("questionId")
        vote_type = data.get("voteType")

        if not question_id or not vote_type:
            return jsonify({"error": "Question ID and vote type required"}), 400

        increment = 1 if vote_type == "up" else -1

        # Update votes
        questions_ref.document(question_id).update({
            'votes': firestore.Increment(increment)
        })

        print(f"✅ Vote recorded for question {question_id}: {vote_type}")
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"❌ Vote question error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to vote", "details": str(e)}), 500


@app.route("/acceptanswer", methods=["POST"])
def accept_answer():
    try:
        data = request.get_json()
        question_id = data.get("questionId")
        answer_id = data.get("answerId")
        user_id = str(data.get("userId"))

        if not all([question_id, answer_id, user_id]):
            return jsonify({"error": "Question ID, Answer ID, and User ID required"}), 400

        # Get question
        question_doc = questions_ref.document(question_id).get()

        if not question_doc.exists:
            return jsonify({"error": "Question not found"}), 404

        question = question_doc.to_dict()

        if str(question.get("userId")) != user_id:
            return jsonify({"error": "Unauthorized: You can only accept answers for your questions"}), 403

        # Update answers array
        answers = question.get('answers', [])
        for answer in answers:
            if answer.get('answerId') == answer_id:
                answer['accepted'] = True
            else:
                answer['accepted'] = False

        questions_ref.document(question_id).update({'answers': answers})

        print(f"✅ Answer {answer_id} accepted for question {question_id}")
        return jsonify({"success": True, "message": "Answer accepted!"}), 200

    except Exception as e:
        print(f"❌ Accept answer error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to accept answer: {str(e)}"}), 500


@app.route("/voteanswer", methods=["POST"])
def vote_answer():
    try:
        data = request.get_json()
        question_id = data.get("questionId")
        answer_id = data.get("answerId")
        vote_type = data.get("voteType")

        if not all([question_id, answer_id, vote_type]):
            return jsonify({"error": "Question ID, Answer ID, and vote type required"}), 400

        if vote_type not in ['up', 'down']:
            return jsonify({"error": "Vote type must be 'up' or 'down'"}), 400

        increment = 1 if vote_type == 'up' else -1

        # Get question
        question_doc = questions_ref.document(question_id).get()

        if not question_doc.exists:
            return jsonify({"error": "Question not found"}), 404

        question = question_doc.to_dict()
        answers = question.get('answers', [])

        # Update specific answer's votes
        for answer in answers:
            if answer.get('answerId') == answer_id:
                answer['votes'] = answer.get('votes', 0) + increment
                break

        questions_ref.document(question_id).update({'answers': answers})

        print(f"✅ Answer {answer_id} voted {vote_type}")
        return jsonify({"success": True, "message": f"Answer {vote_type}voted!"}), 200

    except Exception as e:
        print(f"❌ Vote answer error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to vote on answer: {str(e)}"}), 500


# ==================== NOTIFICATIONS ROUTE ====================

@app.route('/getnotifications', methods=['GET'])
def get_notifications():
    try:
        user_id = str(request.args.get('userId'))
        if not user_id:
            return jsonify({'success': False, 'error': 'User ID required'}), 400

        notifications_data = []

        # Get user's groups
        user_groups = groups_ref.where('members', 'array_contains', user_id).stream()

        for group_doc in user_groups:
            group = group_doc.to_dict()
            group_id = group_doc.id
            project_name = group.get('project_name', 'Unnamed Group')
            created_at = group.get('createdAt')
            created_at_iso = created_at.isoformat() if created_at else datetime.utcnow().isoformat()

            notifications_data.append({
                'id': f'group-{group_id}',
                'type': 'group',
                'name': project_name,
                'avatar': project_name[0:2].upper() if project_name else 'UG',
                'time': created_at_iso,
                'content': f"You joined the group '{project_name}'. Start collaborating!",
                'unread': True,
                'actionUrl': f"mainpage.html#group-{group_id}",
                'createdAt': created_at_iso,
            })

            if str(group.get('creatoruserid')) == user_id and len(group.get('members', [])) > 1:
                member_count = len(group.get('members', []))
                notifications_data.append({
                    'id': f'member-{group_id}',
                    'type': 'activity',
                    'name': 'New Member Alert',
                    'avatar': '👥',
                    'time': created_at_iso,
                    'content': f"Your group '{project_name}' now has {member_count} member{'s' if member_count > 1 else ''}!",
                    'unread': True,
                    'actionUrl': f"mainpage.html#group-{group_id}",
                    'createdAt': created_at_iso,
                })

        notifications_data.append({
            'id': 'system-qa-update',
            'type': 'activity',
            'name': 'Platform Update',
            'avatar': '🎉',
            'time': datetime.utcnow().isoformat(),
            'content': 'New Q&A features are now live! Try asking your first question.',
            'unread': True,
            'actionUrl': 'qa.html',
            'createdAt': datetime.utcnow().isoformat(),
        })

        print(f"✅ Generated {len(notifications_data)} notifications for user {user_id}")
        return jsonify({'success': True, 'notifications': notifications_data}), 200

    except Exception as e:
        print(f"❌ Get notifications error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== DISCUSSION ROUTES ====================

@app.route("/getdiscussions", methods=["GET"])
def get_discussions():
    try:
        user_id = str(request.args.get('userId'))

        if not user_id or user_id == 'None':
            return jsonify({"error": "User ID required"}), 400

        # Get user's groups
        user_groups = groups_ref.where('members', 'array_contains', user_id).stream()
        group_ids = [group_doc.id for group_doc in user_groups]

        if not group_ids:
            return jsonify({"success": True, "discussions": []}), 200

        # Get discussions for these groups
        discussions = discussions_ref.where('groupId', 'in', group_ids).order_by('lastMessageTime', direction=firestore.Query.DESCENDING).limit(50).stream()

        discussions_list = []
        for d_doc in discussions:
            d = d_doc.to_dict()
            discussions_list.append({
                "discussionId": d_doc.id,
                "roomName": d.get("roomName"),
                "topic": d.get("topic", ""),
                "participants": d.get("participants", []),
                "lastMessage": d.get("lastMessage", ""),
                "lastMessageTime": d.get("lastMessageTime").isoformat() if d.get("lastMessageTime") else datetime.utcnow().isoformat(),
                "createdBy": d.get("createdBy"),
                "createdByName": d.get("createdByName", ""),
                "groupId": d.get("groupId"),
                "groupName": d.get("groupName", ""),
                "createdAt": d.get("createdAt").isoformat() if d.get("createdAt") else datetime.utcnow().isoformat()
            })

        print(f"✅ Retrieved {len(discussions_list)} discussions for user {user_id}")
        return jsonify({"success": True, "discussions": discussions_list}), 200
    except Exception as e:
        print(f"❌ Get discussions error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/creatediscussion", methods=["POST"])
def create_discussion():
    try:
        data = request.get_json()
        room_name = data.get("roomName")
        group_id = data.get("groupId")
        user_id = str(data.get("userId"))

        if not all([room_name, group_id, user_id]):
            return jsonify({"error": "Room name, group ID, and user ID required"}), 400

        # Get group
        group_doc = groups_ref.document(group_id).get()

        if not group_doc.exists:
            return jsonify({"error": "Group not found"}), 404

        group = group_doc.to_dict()
        members = [str(m) for m in group.get("members", [])]

        if user_id not in members:
            return jsonify({"error": "You are not a member of this group"}), 403

        discussion_data = {
            "roomName": room_name,
            "topic": data.get("topic", ""),
            "createdBy": user_id,
            "createdByName": data.get("userName"),
            "participants": [user_id],
            "messages": [],
            "lastMessage": "",
            "lastMessageTime": firestore.SERVER_TIMESTAMP,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "groupId": group_id,
            "groupName": group.get("project_name", "")
        }

        # Add discussion to Firestore
        add_res = discussions_ref.add(discussion_data)
        discussion_id = _get_doc_id_from_add_result(add_res) or ""

        print(f"✅ Discussion created: {discussion_data['roomName']} | ID: {discussion_id}")

        return jsonify({
            "success": True,
            "message": "Discussion created!",
            "discussionId": discussion_id
        }), 200
    except Exception as e:
        print(f"❌ Create discussion error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/getmessages/<discussion_id>", methods=["GET"])
def get_messages(discussion_id):
    try:
        user_id = str(request.args.get('userId'))

        if not user_id or user_id == 'None':
            return jsonify({"error": "User ID required"}), 400

        # Get discussion
        discussion_doc = discussions_ref.document(discussion_id).get()

        if not discussion_doc.exists:
            return jsonify({"error": "Discussion not found"}), 404

        discussion = discussion_doc.to_dict()
        group_id = discussion.get("groupId")

        if group_id:
            group_doc = groups_ref.document(group_id).get()
            if not group_doc.exists:
                return jsonify({"error": "Group not found"}), 403

            group = group_doc.to_dict()
            members = [str(m) for m in group.get("members", [])]
            if user_id not in members:
                return jsonify({"error": "Access denied"}), 403

        return jsonify({
            "success": True,
            "messages": discussion.get("messages", []),
            "roomName": discussion.get("roomName"),
            "topic": discussion.get("topic", ""),
            "groupName": discussion.get("groupName", "")
        }), 200
    except Exception as e:
        print(f"❌ Get messages error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/sendmessage", methods=["POST"])
def send_message():
    try:
        data = request.get_json()
        discussion_id = data.get("discussionId")
        user_id = str(data.get("userId"))

        if not discussion_id or not user_id:
            return jsonify({"error": "Discussion ID and User ID required"}), 400

        # Get discussion
        discussion_doc = discussions_ref.document(discussion_id).get()

        if not discussion_doc.exists:
            return jsonify({"error": "Discussion not found"}), 404

        discussion = discussion_doc.to_dict()
        group_id = discussion.get("groupId")

        if group_id:
            group_doc = groups_ref.document(group_id).get()
            if not group_doc.exists:
                return jsonify({"error": "Group not found"}), 403

            group = group_doc.to_dict()
            members = [str(m) for m in group.get("members", [])]
            if user_id not in members:
                return jsonify({"error": "Access denied"}), 403

        message = {
            "messageId": f"{discussion_id}_msg_{int(datetime.utcnow().timestamp())}",
            "userId": user_id,
            "userName": data.get("userName"),
            "userPhoto": data.get("userPhoto", ""),
            "content": data.get("content"),
            "timestamp": datetime.utcnow().isoformat()
        }

        # Update discussion
        discussions_ref.document(discussion_id).update({
            'messages': firestore.ArrayUnion([message]),
            'lastMessage': data.get("content"),
            'lastMessageTime': firestore.SERVER_TIMESTAMP,
            'participants': firestore.ArrayUnion([user_id])
        })

        print(f"✅ Message sent in discussion {discussion_id}")
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"❌ Send message error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ==================== UTILITY ROUTES ====================

@app.route('/health', methods=['GET'])
def health():
    try:
        # Test Firebase connection
        db.collection('_health_check').document('test').set({'timestamp': firestore.SERVER_TIMESTAMP})
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    return jsonify({
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route('/test', methods=['GET'])
def test():
    return jsonify({
        "message": "✅ The Huddle API is working with Firebase!",
        "database": "Firebase Firestore",
        "collections": ["users", "groups", "posts", "questions", "discussions"],
        "endpoints": {
            "auth": ["/signup [POST]", "/login [POST]"],
            "profile": ["/updateprofile [POST]", "/getuser/<user_id> [GET]"],
            "groups": ["/getavailablegroups [GET/POST]", "/creategroup [POST]", "/joingroup [POST]", "/leavegroup [POST]", "/getmygroups [GET]"],
            "posts": ["/createpost [POST]", "/getposts [GET]"],
            "qa": ["/createquestion [POST]", "/getquestions [GET]", "/addanswer [POST]", "/votequestion [POST]", "/acceptanswer [POST]", "/voteanswer [POST]"],
            "discussions": ["/getdiscussions [GET]", "/creatediscussion [POST]", "/getmessages/<id> [GET]", "/sendmessage [POST]"],
            "notifications": ["/getnotifications [GET]"],
            "utility": ["/health [GET]", "/test [GET]"]
        }
    }), 200


# ==================== START SERVER ====================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 THE HUDDLE - STUDENT NETWORKING PLATFORM (FIREBASE)")
    print("="*70)
    print(f"🌐 Server URL:    http://127.0.0.1:5000")
    print(f"🗄️  Database:      Firebase Firestore")
    print(f"✅ Status:        Ready")
    try:
        proj = firebase_admin.get_app().project_id
    except Exception:
        proj = "huddle-c477f"
    print(f"🔥 Using Firebase Project: {proj}")
    print("="*70)
    print("\n📄 Available Pages:")
    print("   • http://127.0.0.1:5000/login.html")
    print("   • http://127.0.0.1:5000/qa.html")
    print("\n🔧 Test Endpoints:")
    print("   • http://127.0.0.1:5000/test")
    print("   • http://127.0.0.1:5000/health")
    print("   • http://127.0.0.1:5000/getquestions")
    print("="*70 + "\n")

    app.run(host="127.0.0.1", port=5000, debug=True)
