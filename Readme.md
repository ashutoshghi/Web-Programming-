# Lab Report Submission

A GitHub repository containing all the completed labs has been created, and all lab repositories are set to **public** as instructed.

## Labs Overview

### LAB 1

**Portfolio with Calendar**

* Technologies: HTML, CSS, JavaScript

### LAB 2

**Introduction to JavaScript**

* Topics: var, let, const, functions, arrow functions, objects, map, filter, spread operators

### LAB 3

**Login & Register Form**

* Technologies: React
* Features: Custom input components, state management

### LAB 4

**Todo CRUD Application**

* Technologies: React
* Features: Create, Read, Update, Delete using state manipulation

### LAB 5

**Backend Auth System**

* Technologies: FastAPI
* Features: Login & Register with authentication
* Includes: Controllers, DB connection, models, migrations, routes

### LAB 6

**User-based Todo Backend**

* Technologies: FastAPI, ORM
* Features: Display todos based on authenticated user
* Includes: Migrations and database integration

---

## How to Run the Labs

### 🔹 Frontend Labs (LAB 1–4)

1. Clone the repository:

   ```bash
   git clone <your-repo-link>
   cd <repo-folder>
   ```

2. For LAB 1 & LAB 2:

   * Open the `index.html` file directly in a browser

3. For LAB 3 & LAB 4 (React apps):

   ```bash
   npm install
   npm start
   ```

   * App will run on: `http://localhost:3000`

---

### 🔹 Backend Labs (LAB 5 & LAB 6)

1. Navigate to backend folder:

   ```bash
   cd backend
   ```

2. Create virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate   # (Linux/Mac)
   venv\Scripts\activate      # (Windows)
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run migrations:

   ```bash
   alembic upgrade head
   ```

5. Start FastAPI server:

   ```bash
   uvicorn main:app --reload
   ```

6. Open in browser:

   * API: [http://127.0.0.1:8000](http://127.0.0.1:8000)
   * Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---
