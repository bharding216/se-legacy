from flask import url_for, current_app, request

def generate_sitemap():
    with current_app.app_context():
        base_url = request.host_url
        sitemap_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        sitemap_xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        for rule in current_app.url_map.iter_rules():
            if "GET" in rule.methods and not bool(rule.arguments):
                endpoint = url_for(rule.endpoint)
                url = base_url.rstrip('/') + endpoint
                sitemap_xml += f'\t<url><loc>{url}</loc></url>\n'
        sitemap_xml += '</urlset>\n'
        return sitemap_xml
    

