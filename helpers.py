from flask import url_for, current_app, request
import pytz

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
    
# Here are the 'pytz' docs: https://pytz.sourceforge.net/
def utc_to_central(datetime_utc):
    utc_timezone = pytz.timezone('UTC')
    central_timezone = pytz.timezone('US/Central')
    datetime_central = datetime_utc.replace(tzinfo=pytz.utc).astimezone(central_timezone)
    return datetime_central

def central_to_utc(datetime_central):
    utc_timezone = pytz.timezone('UTC')
    central_timezone = pytz.timezone('US/Central')
    datetime_utc = datetime_central.replace(tzinfo=central_timezone).astimezone(utc_timezone)
    return datetime_utc