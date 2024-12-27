package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/time/rate"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Product structure represents a product in the store
type Product struct {
	ID    primitive.ObjectID `bson:"_id"`
	Name  string             `bson:"name"`
	Size  string             `bson:"size" json:"size"`
	Price int                `bson:"price" json:"price"`
}

// User structure represents a user in the system
type User struct {
	Username string
	Email    string
	Password string
	Role     string
	otp      string
}

// News structure represents a news article
type News struct {
	Title       string
	Description string
	Source      string
	URL         string
}

var (
	db        *mongo.Database // Adjusted for MongoDB
	log       *logrus.Logger
	limiter   = rate.NewLimiter(1, 3) // Rate limit of 1 request per second with a burst of 3 requests
	templates = template.Must(template.ParseGlob("templates/*.html"))
)

func fetchNewsFromAPI(apiKey, keyword string) ([]News, error) {
	url := fmt.Sprintf("https://newsapi.org/v2/everything?q=%s&apiKey=%s&pageSize=5", keyword, apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response struct {
		Articles []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Source      struct {
				Name string `json:"name"`
			} `json:"source"`
			URL string `json:"url"`
		} `json:"articles"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	var newsList []News
	for _, article := range response.Articles {
		newsList = append(newsList, News{
			Title:       article.Title,
			Description: article.Description,
			Source:      article.Source.Name,
			URL:         article.URL,
		})
	}

	return newsList, nil
}

func initDB() {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb+srv://erkezhan_a_e:AE070120@cluster0.ca1wa.mongodb.net/"))
	if err != nil {
		log.Fatal("Error creating MongoDB client. Please wait, give some time.", err)
	}

	err = client.Ping(context.TODO(), readpref.Primary())
	if err != nil {
		log.Fatal("Error creating MongoDB client. Please wait, give some time.", err)
	}

	db = client.Database("usersAuth")
	log.Info("Connected to MongoDB")

	// In MongoDB, collections are created automatically when you first insert data.
}

func fetchProductsFromDB(filter, sortBy string, page, pageSize int) ([]Product, error) {
	var products []Product

	collection := db.Collection("laptops")
	filterBson := bson.M{}
	if filter != "" {
		filterBson = bson.M{"name": bson.M{"$regex": filter, "$options": "i"}}
	}

	// Sorting
	sortBson := bson.D{}
	if sortBy != "" {
		sortBson = append(sortBson, bson.E{Key: sortBy, Value: 1})
	}

	findOptions := options.Find()
	findOptions.SetSort(sortBson)
	findOptions.SetLimit(int64(pageSize))
	findOptions.SetSkip(int64((page - 1) * pageSize))

	cur, err := collection.Find(context.TODO(), filterBson, findOptions)
	if err != nil {
		log.Error("Error fetching products from MongoDB:", err)
		return nil, err
	}
	defer cur.Close(context.TODO())

	for cur.Next(context.TODO()) {
		var p Product
		err := cur.Decode(&p)
		if err != nil {
			log.Error("Error decoding product document:", err)
			continue
		}
		products = append(products, p)
	}

	if err := cur.Err(); err != nil {
		log.Error("Error iterating over product documents:", err)
		return nil, err
	}

	return products, nil
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		cookie, err := r.Cookie("username")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		username := cookie.Value

		collection := db.Collection("users")

		var user User
		// Use '=' instead of ':=' because 'err' is already declared
		err = collection.FindOne(context.TODO(), bson.M{
			"username": username,
		}).Decode(&user)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if user.Role != "admin" {
			http.Error(w, "You're not an admin", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func sendEmail(to, subject, body string) error {
	from := "awexeoz7z@gmail.com"
	password := "rjuo knag jgru sasi"
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Compose the email message
	message := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	// Connect to the SMTP server
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(message))
	if err != nil {
		return err
	}

	return nil
}

// GenerateOTP generates a random OTP consisting of 6 digits
func GenerateOTP() string {
	// Generate a random number between 0 and 899999.
	randomNum, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		panic(err) // In a production system, you'd probably want to handle this error more gracefully
	}
	// Add 100000 to ensure the number is always 6 digits
	randomNum = randomNum.Add(randomNum, big.NewInt(100000))
	return randomNum.String()
}

func IsLoggedIn(r *http.Request) bool {
	cookie, err := r.Cookie("username")
	if err == nil && cookie != nil && cookie.Value != "" {
		return true
	}
	return false
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template file
	tmpl := templates.Lookup("register.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the template
	tmpl.Execute(w, nil)
}

func RegisterPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := "user" // Default role
	otp := GenerateOTP()

	// Basic validation
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Set role based on username, for example purposes
	if username == "alikhan" || username == "alinur" || username == "yernur" {
		role = "admin"
	}

	collection := db.Collection("users")
	_, err := collection.InsertOne(context.TODO(), bson.M{
		"username": username,
		"email":    email,
		"password": password,
		"role":     role,
		"otp":      otp,
	})

	if err != nil {
		log.Println("Error registering user:", err)
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	sendEmail(email, "Laptop Store", "Welcome! You have been registered! Your OTP is "+otp)
	fmt.Fprintf(w, "User %s successfully registered", username)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template file
	tmpl := templates.Lookup("login.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the template
	tmpl.Execute(w, nil)
}

func LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	otp := r.FormValue("otp")

	// Basic validation
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	var user User
	collection := db.Collection("users")
	err := collection.FindOne(context.TODO(), bson.M{
		"username": username,
		"password": password,
		"otp":      otp,
	}).Decode(&user)

	if err != nil {
		log.Println("Error logging in:", err)
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
	}

	newOTP := GenerateOTP()
	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"username": username},
		bson.M{"$set": bson.M{"otp": newOTP}},
	)

	// Simulate session management by setting a cookie
	expiration := time.Now().Add(24 * time.Hour)
	cookie := http.Cookie{Name: "username", Value: username, Expires: expiration}
	http.SetCookie(w, &cookie)

	sendEmail(user.Email, "OTP Update", "You have been logged in! Your new OTP is "+newOTP)

	// Redirect based on user role
	if user.Role == "admin" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/profile-edit", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the username cookie to log out the user
	cookie := http.Cookie{
		Name:    "username",
		Value:   "",
		Expires: time.Now().Add(-time.Hour), // Set expiration in the past to delete the cookie
	}
	http.SetCookie(w, &cookie)

	// Redirect to the login page or any other page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sort")

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || pageSize < 1 {
		pageSize = 10
	}

	isLoggedIn := IsLoggedIn(r)

	// Rate limiting check
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Fetch products from the database
	products, err := fetchProductsFromDB(filter, sortBy, page, pageSize)
	if err != nil {
		log.Error("Error fetching products from the database:", err)
		http.Error(w, "Error fetching products from the database", http.StatusInternalServerError)
		return
	}

	// Fetch news from NewsAPI
	apiKey := "84b7be9be9f746c8a5a08894ea376461"
	keyword := "fashion" // Replace with appropriate keyword
	newsList, err := fetchNewsFromAPI(apiKey, keyword)
	if err != nil {
		log.Error("Error fetching news from API:", err)
		// Handle the error, e.g., ignore or display an error message
	}

	// Prepare data for the template
	tmpl := templates.Lookup("index.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	data := struct {
		Filter     string
		SortBy     string
		Products   []Product
		Page       int
		PrevPage   int
		NextPage   int
		PageSize   int
		IsLoggedIn bool
		News       []News
	}{
		Filter:     filter,
		SortBy:     sortBy,
		Products:   products,
		Page:       page,
		PrevPage:   page - 1,
		NextPage:   page + 1,
		PageSize:   pageSize,
		IsLoggedIn: isLoggedIn,
		News:       newsList,
	}

	// Render the template with the data
	tmpl.Execute(w, data)
}

func ProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch user profile information from the database based on the logged-in user
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := cookie.Value

	var user User
	err = db.Collection("users").FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		log.Error("Error fetching user profile from MongoDB:", err)
		http.Error(w, "Error fetching user profile from the database", http.StatusInternalServerError)
		return
	}

	// Parse the HTML template file
	tmpl := templates.Lookup("profile-edit.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the template with user profile data
	tmpl.Execute(w, user)
}

func ProfileEditPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	// Fetch user profile information from the form submission
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	update := bson.M{"$set": bson.M{"email": email}}
	if password != "" {
		update["$set"].(bson.M)["password"] = password
	}

	_, err := db.Collection("users").UpdateOne(
		context.TODO(),
		bson.M{"username": username},
		update,
	)
	if err != nil {
		log.Println("Error updating user profile in MongoDB:", err)
		http.Error(w, "Error updating user profile in database", http.StatusInternalServerError)
		return
	}

	// Redirect to the profile page or any other page after successful update
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	sortBy := r.URL.Query().Get("sort")

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || pageSize < 1 {
		pageSize = 10
	}

	// Rate limiting check
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	products, err := fetchProductsFromDB(filter, sortBy, page, pageSize)
	if err != nil {
		log.Error("Error fetching products from the database:", err)
		http.Error(w, "Error fetching products from the database", http.StatusInternalServerError)
		return
	}

	tmpl := templates.Lookup("admin.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	data := struct {
		Filter   string
		SortBy   string
		Products []Product
		Page     int
		PrevPage int
		NextPage int
		PageSize int
	}{
		Filter:   filter,
		SortBy:   sortBy,
		Products: products,
		Page:     page,
		PrevPage: page - 1,
		NextPage: page + 1,
		PageSize: pageSize,
	}

	tmpl.Execute(w, data)
}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/delete/"):]
	// Convert the string ID to a MongoDB ObjectID
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		log.Printf("Error converting ID to ObjectID: %v", err)
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}

	_, err = db.Collection("laptops").DeleteOne(context.TODO(), bson.M{"_id": objectID})
	if err != nil {
		log.Errorf("Error deleting from MongoDB: %v", err)
		http.Error(w, "Error deleting from database", http.StatusInternalServerError)
		return
	}

	log.Printf("Product deleted with ID: %s\n", id)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func AddProductHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := templates.Lookup("add-product.html")
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}

func AddProductPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("name")
	size := r.FormValue("size")
	price, _ := strconv.Atoi(r.FormValue("price")) // Convert price to int

	_, err := db.Collection("laptops").InsertOne(context.TODO(), bson.M{
		"name":  name,
		"size":  size,
		"price": price,
	})
	if err != nil {
		log.Println("Error inserting into MongoDB:", err)
		http.Error(w, "Error inserting into database", http.StatusInternalServerError)
		return
	}

	log.Printf("New product added: Name=%s, Size=%s, Price=%d\n", name, size, price)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func EditProductHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the hex ID from the URL, ensuring it's just the hex string without any encoding.
	hexID := strings.TrimPrefix(r.URL.Path, "/edit/")

	// Log the hexID for debugging purposes
	log.Printf("Hex ID received: %s", hexID)

	// Convert the hex string to an ObjectID.
	objectID, err := primitive.ObjectIDFromHex(hexID)
	if err != nil {
		log.Printf("Error converting hex to ObjectID: %v, hex: %s", err, hexID)
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	// Log the objectID for debugging purposes
	log.Printf("ObjectID to query: %s", objectID.Hex())

	var product Product
	err = db.Collection("laptops").FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&product)
	if err != nil {
		log.Printf("Error fetching product details from MongoDB: %v, ObjectID: %s", err, objectID.Hex())
		http.Error(w, "Error fetching product details", http.StatusInternalServerError)
		return
	}

	tmpl := templates.Lookup("edit-product.html")
	if tmpl == nil {
		log.Println("Template not found")
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, product); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func EditProductPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/edit-product-post/"):]
	// Convert the hex string to an ObjectID
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	// Assuming the price is sent as an integer value in cents (or the smallest currency unit)
	price, err := strconv.Atoi(r.FormValue("price"))
	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}

	_, err = db.Collection("laptops").UpdateOne(
		context.TODO(),
		bson.M{"_id": objectID}, // Use the ObjectID for the update filter
		bson.M{
			"$set": bson.M{
				"name":  r.FormValue("name"),
				"size":  r.FormValue("size"),
				"price": price,
			},
		},
	)
	if err != nil {
		log.Println("Error updating product in MongoDB:", err)
		http.Error(w, "Error updating product in database", http.StatusInternalServerError)
		return
	}

	log.Printf("Product updated with ID: %s\n", objectID.Hex())

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func SupportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		return
	}

	// Получение данных из формы
	senderEmail := r.FormValue("email")
	message := r.FormValue("message")

	if senderEmail == "" || message == "" {
		http.Error(w, "Email and message are required", http.StatusBadRequest)
		return
	}

	// Формирование письма для отправки в поддержку
	subject := "Support Request"
	body := fmt.Sprintf("You have received a new support request:\n\nFrom: %s\n\nMessage:\n%s", senderEmail, message)

	// Отправка на почту поддержки
	err := sendEmail("yerkezhanakhmetova@gmail.com", subject, body)
	if err != nil {
		log.Println("Error sending email:", err)
		http.Error(w, "Failed to send support message", http.StatusInternalServerError)
		return
	}

	// Ответ клиенту
	fmt.Fprintln(w, "Support request sent successfully!")
}

func main() {
	// Initialize logger
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	file, err := os.OpenFile("logfile.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err == nil {
		log.SetOutput(io.MultiWriter(file, os.Stdout))
	} else {
		log.Error("Failed to log to file, using default stderr")
	}

	// Initialize MongoDB client
	initDB() // Adjusted to not assign to db since initDB() now sets the global variable directly

	// Set up HTTP server
	server := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: nil, // Your handler will be set later
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Set up routes
	http.HandleFunc("/register", RegisterHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/register-post", RegisterPostHandler)
	http.HandleFunc("/login-post", LoginPostHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/", IndexHandler)
	http.Handle("/admin", AuthMiddleware(http.HandlerFunc(AdminHandler)))
	http.HandleFunc("/profile-edit", ProfileEditHandler)
	http.HandleFunc("/profile-edit-post", ProfileEditPostHandler)
	http.HandleFunc("/delete/", DeleteHandler)
	http.HandleFunc("/add-product", AddProductHandler)
	http.HandleFunc("/add-product-post", AddProductPostHandler)
	http.HandleFunc("/edit/", EditProductHandler)
	http.HandleFunc("/edit-product-post/", EditProductPostHandler)
	http.HandleFunc("/support", SupportHandler)

	// Run server in a goroutine for graceful shutdown
	go func() {
		log.Println("Server is running at http://127.0.0.1:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server error:", err)
		}
	}()

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Server is shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server shutdown error:", err)
	}

	log.Info("Server has stopped")
}
