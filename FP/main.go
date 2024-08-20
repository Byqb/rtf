package main

import (
    "crypto/rand"
    "database/sql"
    "fmt"
    "html/template"
    "log"
		"os"
    "net/http"
    "time"
    "encoding/json"
    "golang.org/x/crypto/bcrypt"
    _ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var tpl *template.Template

type User struct {
    ID       int
    Username string
    Email    string
    Password string
}

type Post struct {
    ID         int
    UserID     int
    Username   string
    Title      string
    Content    string
    CreatedAt  time.Time
    Likes      int
    Dislikes   int
    Categories []string
    Comments   []Comment
}

type Comment struct {
    ID         int
    PostID     int
    UserID     int
    Username   string
    Content    string
    CreatedAt  time.Time
    Likes      int
    Dislikes   int
}

func init() {
    var err error
    db, err = sql.Open("sqlite3", "./forum.db")
    if err != nil {
        log.Fatal(err)
    }

    // Create tables
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            created_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id INTEGER,
            content TEXT,
            created_at DATETIME,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS post_categories (
            post_id INTEGER,
            category_id INTEGER,
            PRIMARY KEY (post_id, category_id),
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (category_id) REFERENCES categories(id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS post_likes (
            post_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (post_id, user_id),
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS post_dislikes (
            post_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (post_id, user_id),
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comment_likes (
            comment_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (comment_id, user_id),
            FOREIGN KEY (comment_id) REFERENCES comments(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS comment_dislikes (
            comment_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (comment_id, user_id),
            FOREIGN KEY (comment_id) REFERENCES comments(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal(err)
    }
tpl = template.Must(template.New("").Parse(`    
      <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Neon Forum</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #121212; /* Dark background for neon effect */
            color: #e0e0e0; /* Light text color */
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            max-width: 100%;
            overflow-x: hidden;
        }
        h1, h2 {
            color: #00ffff; /* Neon cyan */
            text-shadow: 0 0 10px rgba(0, 255, 255, 0.7); /* Neon glow effect */
            margin: 0;
        }
        .welcome-container {
            text-align: center;
            margin-bottom: 40px;
        }
        .welcome-container p {
            font-size: 1.2em;
            margin: 10px 0;
            color: #00ffff; /* Neon cyan */
        }
        .welcome-container a {
            color: #ff00ff; /* Neon magenta */
            text-decoration: none;
            font-weight: bold;
            transition: color 0.3s;
        }
        .welcome-container a:hover {
            color: #00ffff; /* Neon cyan */
        }
        form {
            background-color: #1e1e1e; /* Dark form background */
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.5); /* Neon glow effect */
            max-width: 400px;
            width: 100%;
            margin: 20px auto;
        }
        input, textarea, select {
            display: block;
            width: calc(100% - 20px);
            margin-bottom: 10px;
            padding: 10px;
            border: 1px solid #00ffff; /* Neon cyan border */
            border-radius: 5px;
            background-color: #333; /* Dark input background */
            color: #fff; /* Text color */
            box-sizing: border-box;
        }
        input[type="submit"], input[type="button"] {
            background-color: #00ffff; /* Neon cyan */
            border: none;
            color: #000;
            padding: 10px;
            text-transform: uppercase;
            font-weight: bold;
            cursor: pointer;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.7); /* Neon glow effect */
            transition: background-color 0.3s, box-shadow 0.3s;
            width: 100%;
        }
        input[type="submit"]:hover, input[type="button"]:hover {
            background-color: #ff00ff; /* Neon magenta */
            box-shadow: 0 0 20px rgba(255, 0, 255, 0.9); /* Stronger neon glow */
        }
        .post, .comment {
            background-color: #1e1e1e; /* Dark background for posts and comments */
            border: 1px solid #333; /* Slight border */
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.5); /* Neon glow effect */
            max-width: 800px;
            width: 100%;
        }
        .error {
            color: #ff0000; /* Neon red */
        }
        .success {
            color: #00ff00; /* Neon green */
        }
        a {
            color: #00ffff; /* Neon cyan */
            text-decoration: none;
            transition: color 0.3s;
        }
        a:hover {
            color: #ff00ff; /* Neon magenta */
            text-decoration: underline;
        }
        @media (max-width: 600px) {
            .welcome-container p {
                font-size: 1em;
            }
            form {
                padding: 15px;
            }
            input, textarea, select {
                padding: 8px;
            }
            input[type="submit"], input[type="button"] {
                padding: 8px;
            }
            .post, .comment {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <h1>Neon Forum</h1>

    <div class="welcome-container">
        {{if .User}}
            <p>Welcome, {{.User.Username}}! <a href="/logout">Logout</a></p>
        {{else}}
            <h2>Login</h2>
            <form action="/login" method="POST">
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="submit" value="Login">
            </form>
            <h2>Register</h2>
            <form action="/register" method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="submit" value="Register">
            </form>
        {{end}}
    </div>

    <h2>Filter Posts</h2>
    <form action="/filter" method="GET">
        <input type="text" name="category" placeholder="Category">
        <input type="submit" value="Apply Filter">
    </form>

    {{if .Error}}
        <p class="error">{{.Error}}</p>
    {{end}}

    {{if .Success}}
        <p class="success">{{.Success}}</p>
    {{end}}

    {{if .User}}
        <h2>Create Post</h2>
        <form action="/post" method="POST">
            <input type="text" name="title" placeholder="Title" required>
            <textarea name="content" placeholder="Content" required></textarea>
            <select name="categories" multiple>
                <option value="general">General</option>
                <option value="technology">Technology</option>
                <option value="sports">Sports</option>
            </select>
            <input type="submit" value="Submit Post">
        </form>
    {{end}}

    <h2>Recent Posts</h2>
    {{range .Posts}}
        <div class="post">
            <h3>{{.Title}}</h3>
            <p>{{.Content}}</p>
            <p>Categories: {{range .Categories}}{{.}} {{end}}</p>
            <small>Posted by {{.Username}} at {{.CreatedAt}}</small>
            <p>Likes: {{.Likes}} | Dislikes: {{.Dislikes}}</p>
            {{if $.User}}
                <!-- Like Form -->
                <form action="/like" method="POST">
                    <input type="hidden" name="post_id" value="{{.ID}}">
                    <input type="submit" value="Like">
                </form>
                <!-- Dislike Form -->
                <form action="/dislike" method="POST">
                    <input type="hidden" name="post_id" value="{{.ID}}">
                    <input type="submit" value="Dislike">
                </form>
                <!-- Comment Form -->
                <form action="/comment" method="POST">
                    <input type="hidden" name="post_id" value="{{.ID}}">
                    <textarea name="content" placeholder="Add a comment" required></textarea>
                    <input type="submit" value="Add Comment">
                </form>
            {{end}}
            <h4>Comments:</h4>
            {{range .Comments}}
                <div class="comment">
                    <p>{{.Content}}</p>
                    <small>Commented by {{.Username}} at {{.CreatedAt}}</small>
                    <p>Likes: {{.Likes}} | Dislikes: {{.Dislikes}}</p>
                    {{if $.User}}
                        <!-- Like Comment Form -->
                        <form action="/like_comment" method="POST">
                            <input type="hidden" name="comment_id" value="{{.ID}}">
                            <input type="submit" value="Like">
                        </form>
                        <!-- Dislike Comment Form -->
                        <form action="/dislike_comment" method="POST">
                            <input type="hidden" name="comment_id" value="{{.ID}}">
                            <input type="submit" value="Dislike">
                        </form>
                    {{end}}
                </div>
            {{end}}
        </div>
    {{end}}
</body>
</html>

	`))
		
}

func main() {

	err := os.MkdirAll("./data", os.ModePerm)
	if err != nil {
			log.Fatal("Failed to create directory:", err)
	}

	// Open the SQLite database
	db, err := sql.Open("sqlite3", "./data/database.db")
	if err != nil {
			log.Fatal("Error opening database:", err)
	}
	defer db.Close()

    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/logout", logoutHandler)
    http.HandleFunc("/post", postHandler)
    http.HandleFunc("/comment", commentHandler)
    http.HandleFunc("/filter", filterHandler)
    http.HandleFunc("/like", likePostHandler)
    http.HandleFunc("/dislike", dislikePostHandler)
    http.HandleFunc("/like_comment", likeCommentHandler)
    http.HandleFunc("/dislike_comment", dislikeCommentHandler)

    fmt.Println("Server is running on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    user := getUser(r)

    category := r.URL.Query().Get("category")

    posts, err := getPosts(category, time.Time{}, false, user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    categories, err := getCategories()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    data := struct {
        User      *User
        Posts     []Post
        Categories []string
        Error     string
        Success   string
    }{
        User:      user,
        Posts:     posts,
        Categories: categories,
    }

    err = tpl.Execute(w, data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}




func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    email := r.FormValue("email")
    password := r.FormValue("password")

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    _, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        username, email, hashedPassword)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    email := r.FormValue("email")
    password := r.FormValue("password")

    var hashedPassword string
    var userID int
    err := db.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&userID, &hashedPassword)
    if err != nil {
        http.Error(w, "Invalid email or password", http.StatusUnauthorized)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err != nil {
        http.Error(w, "Invalid email or password", http.StatusUnauthorized)
        return
    }

    sessionID := generateSessionID()
    expiresAt := time.Now().Add(24 * time.Hour)
    _, err = db.Exec("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
        sessionID, userID, expiresAt)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        Expires:  expiresAt,
        HttpOnly: true,
    })

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie("session_id")
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    _, err = db.Exec("DELETE FROM sessions WHERE id = ?", cookie.Value)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:    "session_id",
        Value:   "",
        Expires: time.Now().Add(-time.Hour),
        HttpOnly: true,
    })

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getUser(r *http.Request) *User {
	cookie, err := r.Cookie("session_id")
	if err != nil {
			return nil
	}

	var userID int
	err = db.QueryRow("SELECT user_id FROM sessions WHERE id = ?", cookie.Value).Scan(&userID)
	if err != nil {
			return nil
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
			return nil
	}

	return &User{
			ID:       userID,
			Username: username,
	}
}


func generateSessionID() string {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        log.Fatal(err)
    }
    return fmt.Sprintf("%x", b)
}

func postHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    user := getUser(r)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    title := r.FormValue("title")
    content := r.FormValue("content")
    categories := r.Form["categories"]

    result, err := db.Exec("INSERT INTO posts (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
        user.ID, title, content, time.Now())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    postID, err := result.LastInsertId()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    for _, category := range categories {
        var categoryID int
        err := db.QueryRow("SELECT id FROM categories WHERE name = ?", category).Scan(&categoryID)
        if err != nil {
            _, err = db.Exec("INSERT INTO categories (name) VALUES (?)", category)
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }
            err = db.QueryRow("SELECT id FROM categories WHERE name = ?", category).Scan(&categoryID)
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }
        }

        _, err = db.Exec("INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)",
            postID, categoryID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func commentHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    user := getUser(r)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    postID := r.FormValue("post_id")
    content := r.FormValue("content")

    _, err := db.Exec("INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
        postID, user.ID, content, time.Now())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getPosts(category string, createdAfter time.Time, liked bool, user *User) ([]Post, error) {
    var posts []Post
    var query string
    var args []interface{}

    // Base query
    query = `
        SELECT p.id, p.user_id, p.title, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) AS likes,
               (SELECT COUNT(*) FROM post_dislikes WHERE post_id = p.id) AS dislikes
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE 1 = 1
    `

    // Add filters
    if category != "" {
        query += ` AND p.id IN (SELECT post_id FROM post_categories pc JOIN categories c ON pc.category_id = c.id WHERE c.name = ?)`
        args = append(args, category)
    }
    if !createdAfter.IsZero() {
        query += ` AND p.created_at > ?`
        args = append(args, createdAfter)
    }
    if liked && user != nil {
        query += ` AND p.id IN (SELECT post_id FROM post_likes WHERE user_id = ?)`
        args = append(args, user.ID)
    }

    rows, err := db.Query(query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var post Post
        err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &post.CreatedAt, &post.Username, &post.Likes, &post.Dislikes)
        if err != nil {
            return nil, err
        }

        // Retrieve comments and categories
        comments, err := getCommentsForPost(post.ID)
        if err != nil {
            return nil, err
        }
        post.Comments = comments

        categories, err := getCategoriesForPost(post.ID)
        if err != nil {
            return nil, err
        }
        post.Categories = categories

        posts = append(posts, post)
    }

    return posts, nil
}


func getCommentsForPost(postID int) ([]Comment, error) {
	var comments []Comment

	rows, err := db.Query(`
			SELECT c.id, c.post_id, c.user_id, c.content, c.created_at, u.username,
						 (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id) AS likes,
						 (SELECT COUNT(*) FROM comment_dislikes WHERE comment_id = c.id) AS dislikes
			FROM comments c
			JOIN users u ON c.user_id = u.id
			WHERE c.post_id = ?
	`, postID)
	if err != nil {
			return nil, err
	}
	defer rows.Close()

	for rows.Next() {
			var comment Comment
			err := rows.Scan(&comment.ID, &comment.PostID, &comment.UserID, &comment.Content, &comment.CreatedAt, &comment.Username, &comment.Likes, &comment.Dislikes)
			if err != nil {
					return nil, err
			}
			comments = append(comments, comment)
	}

	return comments, nil
}

func getCategories() ([]string, error) {
    var categories []string

    rows, err := db.Query("SELECT name FROM categories")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var category string
        err := rows.Scan(&category)
        if err != nil {
            return nil, err
        }
        categories = append(categories, category)
    }

    return categories, nil
}


func getCategoriesForPost(postID int) ([]string, error) {
    var categories []string

    rows, err := db.Query(`
        SELECT c.name
        FROM categories c
        JOIN post_categories pc ON c.id = pc.category_id
        WHERE pc.post_id = ?
    `, postID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        var category string
        err := rows.Scan(&category)
        if err != nil {
            return nil, err
        }
        categories = append(categories, category)
    }

    return categories, nil
}

type FilterCriteria struct {
    Category   string `json:"category"`
}

func filterHandler(w http.ResponseWriter, r *http.Request) {
    category := r.URL.Query().Get("category")

    // Build SQL query based on filter criteria
    query := `
    SELECT p.id, p.user_id, p.title, p.content, p.created_at, u.username,
           (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) AS likes,
           (SELECT COUNT(*) FROM post_dislikes WHERE post_id = p.id) AS dislikes
    FROM posts p
    JOIN users u ON p.user_id = u.id
    WHERE 1=1
    `
    var args []interface{}
    
    if category != "" {
        query += ` AND p.id IN (
            SELECT post_id 
            FROM post_categories pc 
            JOIN categories c ON pc.category_id = c.id 
            WHERE c.name = ?)`
        args = append(args, category)
    }

    rows, err := db.Query(query, args...)
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    // Collect posts
    var posts []Post
    for rows.Next() {
        var post Post
        err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &post.CreatedAt, &post.Username, &post.Likes, &post.Dislikes)
        if err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        // Retrieve comments and categories
        comments, err := getCommentsForPost(post.ID)
        if err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        post.Comments = comments

        categories, err := getCategoriesForPost(post.ID)
        if err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        post.Categories = categories

        posts = append(posts, post)
    }

    // Respond with JSON
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(posts); err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    }
}


func likePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
	}

	user := getUser(r)
	if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
	}

	postID := r.FormValue("post_id")

	// Check if the user has already liked the post
	var liked bool
	row := db.QueryRow("SELECT EXISTS(SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?)", postID, user.ID)
	err := row.Scan(&liked)
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}

	// If already liked, remove the like (toggle behavior)
	if liked {
			_, err := db.Exec("DELETE FROM post_likes WHERE post_id = ? AND user_id = ?", postID, user.ID)
			if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
			}
	} else {
			// Remove dislike if it exists
			_, err := db.Exec("DELETE FROM post_dislikes WHERE post_id = ? AND user_id = ?", postID, user.ID)
			if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
			}

			// Add like
			_, err = db.Exec("INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)", postID, user.ID)
			if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
			}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}



func dislikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
	}

	user := getUser(r)
	if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
	}

	postID := r.FormValue("post_id")

	// Check if the user has already disliked the post
	var disliked bool
	row := db.QueryRow("SELECT EXISTS(SELECT 1 FROM post_dislikes WHERE post_id = ? AND user_id = ?)", postID, user.ID)
	err := row.Scan(&disliked)
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
	}

	// If already disliked, remove the dislike (toggle behavior)
	if disliked {
			_, err := db.Exec("DELETE FROM post_dislikes WHERE post_id = ? AND user_id = ?", postID, user.ID)
			if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
			}
	} else {
			// Remove like if it exists
			_, err := db.Exec("DELETE FROM post_likes WHERE post_id = ? AND user_id = ?", postID, user.ID)
			if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
			}

			// Add dislike
			_, err = db.Exec("INSERT INTO post_dislikes (post_id, user_id) VALUES (?, ?)", postID, user.ID)
			if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
			}
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}


func likeCommentHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    user := getUser(r)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    commentID := r.FormValue("comment_id")

    // Check if the user has already liked the comment
    var liked bool
    row := db.QueryRow("SELECT EXISTS(SELECT 1 FROM comment_likes WHERE comment_id = ? AND user_id = ?)", commentID, user.ID)
    err := row.Scan(&liked)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // If already liked, remove the like (toggle behavior)
    if liked {
        _, err := db.Exec("DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentID, user.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    } else {
        // Remove dislike if it exists
        _, err := db.Exec("DELETE FROM comment_dislikes WHERE comment_id = ? AND user_id = ?", commentID, user.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Add like
        _, err = db.Exec("INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?)", commentID, user.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func dislikeCommentHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    user := getUser(r)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    commentID := r.FormValue("comment_id")

    // Check if the user has already disliked the comment
    var disliked bool
    row := db.QueryRow("SELECT EXISTS(SELECT 1 FROM comment_dislikes WHERE comment_id = ? AND user_id = ?)", commentID, user.ID)
    err := row.Scan(&disliked)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // If already disliked, remove the dislike (toggle behavior)
    if disliked {
        _, err := db.Exec("DELETE FROM comment_dislikes WHERE comment_id = ? AND user_id = ?", commentID, user.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    } else {
        // Remove like if it exists
        _, err := db.Exec("DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?", commentID, user.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Add dislike
        _, err = db.Exec("INSERT INTO comment_dislikes (comment_id, user_id) VALUES (?, ?)", commentID, user.ID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }

    http.Redirect(w, r, "/", http.StatusSeeOther)
}
