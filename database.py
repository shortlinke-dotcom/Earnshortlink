from supabase import create_client

SUPABASE_URL = "https://eotflgeayccsfwujobhd.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVvdGZsZ2VheWNjc2Z3dWpvYmhkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MjI3ODM4OCwiZXhwIjoyMDk3ODU0Mzg4fQ.CShjE0CbiIfKaFV8_2I6MW1vE14KUiv0Q_ic6N_ZkCQ"

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)
