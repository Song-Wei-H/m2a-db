CREATE TABLE IF NOT EXISTS project_memory (
    id SERIAL PRIMARY KEY,
    memory_key VARCHAR(100) UNIQUE NOT NULL,
    category VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_project_memory_key
ON project_memory(memory_key);

CREATE INDEX IF NOT EXISTS idx_project_memory_category
ON project_memory(category);