from flask import Flask, request, render_template

app = Flask(name)

def get_all_links():
# sementara pakai dummy dulu
return [
{“type”: “ads”, “title”: “Ads 1”},
{“type”: “sell”, “title”: “Sell 1”},
{“type”: “ads”, “title”: “Ads 2”},
{“type”: “sell”, “title”: “Sell 2”},
{“type”: “ads”, “title”: “Ads 3”},
{“type”: “sell”, “title”: “Sell 3”},
{“type”: “ads”, “title”: “Ads 4”},
]

@app.route(”/”)
def main():
page = request.args.get(“page”, 1, type=int)

per_page = 5
all_links = get_all_links()
total_data = len(all_links)
start = (page - 1) * per_page
end = start + per_page
paginated_links = all_links[start:end]
total_pages = (total_data + per_page - 1) // per_page
return render_template(
    "main.html",
    links=paginated_links,
    page=page,
    total_pages=total_pages
)

if name == “main”:
app.run(debug=True)
