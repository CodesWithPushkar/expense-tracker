-- Create a new database for your application.
-- It's best practice to not use the default 'test' or 'mysql' databases.
CREATE DATABASE IF NOT EXISTS expense_tracker_db;

-- Switch to using your new database.
USE expense_tracker_db;

-- Create the 'categories' table.
-- This table stores each expense category the user can choose from.
CREATE TABLE IF NOT EXISTS categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    icon VARCHAR(255) NOT NULL,
    color VARCHAR(255) NOT NULL,
    budget DECIMAL(10, 2) DEFAULT 0.00
);

-- Create the 'expenses' table.
-- This table stores the main information for each expense transaction.
CREATE TABLE IF NOT EXISTS expenses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    description TEXT,
    totalAmount DECIMAL(10, 2) NOT NULL,
    date DATETIME NOT NULL
);

-- Create the 'expense_items' table.
-- This is a "join table" that links an expense to its multiple categories.
CREATE TABLE IF NOT EXISTS expense_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    expense_id INT NOT NULL,
    category_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (expense_id) REFERENCES expenses(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

-- Create the 'ious' table.
-- This table tracks money lent to or borrowed from friends.
CREATE TABLE IF NOT EXISTS ious (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type ENUM('lent', 'borrowed') NOT NULL,
    person VARCHAR(255) NOT NULL,
    description TEXT,
    amount DECIMAL(10, 2) NOT NULL,
    date DATETIME NOT NULL,
    status ENUM('open', 'settled') NOT NULL DEFAULT 'open'
);

-- Insert some default categories so the app has data to start with.
-- The IGNORE keyword prevents errors if you run this script multiple times.
INSERT IGNORE INTO categories (name, icon, color, budget) VALUES
('Snacks', 'ph-cookie', 'text-blue-500', 0),
('Vegetables', 'ph-carrot', 'text-green-500', 0),
('Stationery', 'ph-pencil-line', 'text-yellow-500', 0),
('Milk', 'ph-drop', 'text-gray-500', 0),
('Travel', 'ph-bus', 'text-purple-500', 0),
('Other', 'ph-dots-three', 'text-red-500', 0);

