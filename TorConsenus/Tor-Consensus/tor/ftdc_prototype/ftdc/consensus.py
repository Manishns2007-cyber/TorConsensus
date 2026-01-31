"""Enhanced Onionoo-based consensus collector for Tor relays."""
import json
import time
from datetime import datetime, timedelta

import requests
import urllib3

# Disable SSL warnings for demo/hackathon environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TorConsensusCollector:
    def __init__(self, limit=500, cache_duration=3600):
        self.summary_url = f"https://onionoo.torproject.org/summary?limit={limit}"
        self.details_url = f"https://onionoo.torproject.org/details?limit={limit}"
        self.relay_metadata = []
        self.detailed_relays = []
        self.cache_duration = cache_duration
        self.last_fetch = None
        self.cache = {}
        self.headers = {
            'User-Agent': 'TOR-Unveil/1.0 (TN Police Hackathon 2025; Research Tool)'
        }
        # Track if the remote Onionoo API is unavailable so we can
        # immediately use local fallback data instead of repeatedly
        # attempting slow network requests (important for offline/demo use).
        self.api_failed = False
        self.api_health_status = {'status': 'unknown', 'last_check': None, 'consecutive_failures': 0}
        self.auto_refresh_enabled = False
        self._refresh_thread = None

    def fetch_consensus(self, force_refresh=False):
        """Fetch the latest Tor relay summary via Onionoo JSON with caching."""
        # If we've already determined that the API is unreachable and the
        # caller isn't explicitly forcing a refresh, immediately return
        # cached or fallback data. This prevents the UI from feeling "stuck"
        # when there is no Internet/DNS access.
        if not force_refresh and self.api_failed:
            return self.cache.get('summary') or self._generate_fallback_data()

        if not force_refresh and self.last_fetch:
            if datetime.now() - self.last_fetch < timedelta(seconds=self.cache_duration):
                return self.cache.get('summary')
        
        try:
            # For demo/hackathon: disable SSL verification to bypass certificate issues
            # Use short timeout (3s) to fail fast if API is unreachable
            response = requests.get(self.summary_url, timeout=3, verify=False, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            self.cache['summary'] = data
            self.last_fetch = datetime.now()
            return data
        except (requests.RequestException, ValueError) as exc:
            print(f"⚠️  Onionoo API unavailable: {exc}")
            # Mark API as failed so subsequent calls short‑circuit to
            # fallback data without incurring more network delays.
            self.api_failed = True
            if 'summary' not in self.cache:
                self.cache['summary'] = self._generate_fallback_data()
            return self.cache.get('summary')
    
    def check_api_health(self):
        """Check if Onionoo API is reachable and update health status."""
        try:
            response = requests.head(self.summary_url, timeout=5, verify=False)
            if response.status_code == 200:
                self.api_health_status = {
                    'status': 'healthy',
                    'last_check': datetime.now(),
                    'consecutive_failures': 0
                }
                self.api_failed = False
                return True
            else:
                self._mark_api_unhealthy()
                return False
        except Exception as e:
            self._mark_api_unhealthy()
            print(f"API health check failed: {e}")
            return False
    
    def _mark_api_unhealthy(self):
        """Mark API as unhealthy and track failures."""
        self.api_health_status['consecutive_failures'] += 1
        self.api_health_status['status'] = 'unhealthy'
        self.api_health_status['last_check'] = datetime.now()
        if self.api_health_status['consecutive_failures'] >= 3:
            self.api_failed = True
    
    def enable_auto_refresh(self, interval_seconds=3600):
        """Enable automatic background refresh of consensus data."""
        import threading
        
        def refresh_worker():
            while self.auto_refresh_enabled:
                time.sleep(interval_seconds)
                if self.auto_refresh_enabled:
                    print("[Auto-refresh] Updating TOR consensus data...")
                    self.fetch_consensus(force_refresh=True)
                    self.fetch_detailed_consensus(force_refresh=True)
        
        self.auto_refresh_enabled = True
        self._refresh_thread = threading.Thread(target=refresh_worker, daemon=True)
        self._refresh_thread.start()
        print(f"[Auto-refresh] Enabled with {interval_seconds}s interval")
    
    def disable_auto_refresh(self):
        """Disable automatic background refresh."""
        self.auto_refresh_enabled = False
        if self._refresh_thread:
            print("[Auto-refresh] Disabled")
    
    def fetch_detailed_consensus(self, force_refresh=False):
        """Fetch detailed relay information including uptime, exit policies, bandwidth history."""
        # If the summary API has already been marked as failed, skip any
        # further attempts to contact the details endpoint unless we are
        # explicitly forcing a refresh.
        if not force_refresh and self.api_failed:
            return self.cache.get('details')

        if not force_refresh and 'details' in self.cache:
            return self.cache['details']
        
        try:
            # For demo/hackathon: disable SSL verification to bypass certificate issues
            # Use short timeout (5s) to fail fast if API is unreachable
            response = requests.get(self.details_url, timeout=5, verify=False, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            self.cache['details'] = data
            return data
        except requests.RequestException as exc:
            print(f"Error fetching detailed consensus: {exc}")
            # Also mark API as failed so future calls won't keep retrying
            # the remote endpoint when offline.
            self.api_failed = True
            return self.cache.get('details')

    def parse_consensus(self, consensus_data, detailed_data=None):
        """Parse Onionoo JSON and return structured relay metadata with detailed info."""
        if not consensus_data:
            return []
        raw_relays = consensus_data.get("relays", [])
        detailed_map = {}
        
        if detailed_data:
            for relay in detailed_data.get("relays", []):
                detailed_map[relay.get("fingerprint")] = relay
        
        parsed = []
        for relay in raw_relays:
            # Handle both real Onionoo format and fallback format
            fingerprint = relay.get("fingerprint") or relay.get("f")
            or_addresses = relay.get("or_addresses") or relay.get("a", [])
            ip = None
            or_port = None
            if or_addresses:
                addr = or_addresses[0]
                if ":" in addr:
                    parts = addr.rsplit(":", 1)
                    ip = parts[0].strip("[]")
                    try:
                        or_port = int(parts[1])
                    except ValueError:
                        or_port = None
                else:
                    ip = addr
            
            detailed = detailed_map.get(fingerprint, {})
            
            # Handle both real and fallback format
            nickname = relay.get("nickname") or relay.get("n", f"Relay{len(parsed)}")

            # Normalize flags so downstream code can safely use "in flags" checks
            raw_flags = relay.get("flags") or relay.get("r", [])
            if isinstance(raw_flags, (list, tuple)):
                flags = list(raw_flags)
            elif isinstance(raw_flags, str):
                # Some implementations might return a space- or comma-separated string
                if "," in raw_flags:
                    flags = [f.strip() for f in raw_flags.split(",") if f.strip()]
                else:
                    flags = [f.strip() for f in raw_flags.split() if f.strip()]
            else:
                # Protect against booleans or other non-iterables
                flags = []

            country = relay.get("country") or relay.get("c", "XX")
            
            # Get geographic coordinates and AS info from detailed data
            latitude = None
            longitude = None
            as_number = None
            as_name = None
            city = None
            region = None
            
            if detailed:
                latitude = detailed.get("latitude")
                longitude = detailed.get("longitude")
                # AS info can be in 'as' or 'as_number' fields
                as_field = detailed.get("as") or detailed.get("as_number") or detailed.get("as_name")
                if as_field:
                    # Parse AS field like "AS24940" or "AS24940 Hetzner Online GmbH"
                    if isinstance(as_field, str):
                        parts = as_field.split()
                        if parts and parts[0].startswith('AS'):
                            as_number = parts[0].replace('AS', '')
                            as_name = ' '.join(parts[1:]) if len(parts) > 1 else None
                        else:
                            as_name = as_field
                    else:
                        as_number = str(as_field)
                
                # Get additional AS name if not already set
                if not as_name:
                    as_name = detailed.get("as_name")
                
                city = detailed.get("city_name")
                region = detailed.get("region_name")
                
                # Update country if available in detailed
                if detailed.get("country"):
                    country = detailed.get("country")
            
            # If critical data is missing and we have an IP, use IP geolocation lookup
            if ip and (country == "XX" or not as_number or not city or not latitude):
                geo_data = self._get_ip_geolocation(ip)
                
                # Use geo_data to fill in missing fields
                if country == "XX" and geo_data.get('country_code') != 'XX':
                    country = geo_data.get('country_code', 'XX')
                
                if not city:
                    city = geo_data.get('city')
                
                if not region:
                    region = geo_data.get('region')
                
                if not latitude:
                    latitude = geo_data.get('latitude')
                    longitude = geo_data.get('longitude')
                
                if not as_number:
                    as_number = geo_data.get('as_number')
                
                if not as_name:
                    as_name = geo_data.get('as_name') or geo_data.get('isp')
            
            # If not in detailed, try to get from country mapping (approximate)
            if latitude is None or longitude is None:
                lat, lon = self._get_country_coordinates(country)
                latitude = latitude or lat
                longitude = longitude or lon
            
            entry = {
                "fingerprint": fingerprint,
                "nickname": nickname,
                "ip": ip,
                "or_port": or_port,
                "flags": flags,
                "bandwidth": relay.get("advertised_bandwidth") or relay.get("consensus_weight") or 1000000,
                "country": country,
                "country_code": country,
                "country_name": self._get_country_name(country),
                "latitude": latitude,
                "longitude": longitude,
                "as_number": as_number,
                "as_name": as_name or "Unknown ASN",
                "city": city,
                "region": region,
                "first_seen": detailed.get("first_seen", "2024-01-01"),
                "last_seen": detailed.get("last_seen", datetime.now().strftime("%Y-%m-%d")),
                "uptime": detailed.get("uptime", 86400),
                "exit_policy": detailed.get("exit_policy_summary", {}),
                "contact": detailed.get("contact"),
                "platform": detailed.get("platform"),
                "version": detailed.get("version"),
                "bandwidth_rate": detailed.get("bandwidth_rate"),
                "bandwidth_burst": detailed.get("bandwidth_burst"),
                "observed_bandwidth": detailed.get("observed_bandwidth"),
            }
            parsed.append(entry)
        
        self.relay_metadata = parsed
        return parsed
    
    def get_guard_relays(self):
        """Filter and return only Guard relays."""
        guards = []
        for r in self.relay_metadata:
            flags = r.get('flags', [])
            if not isinstance(flags, (list, tuple)):
                continue
            if 'Guard' in flags:
                guards.append(r)
        return guards
    
    def get_exit_relays(self):
        """Filter and return only Exit relays."""
        exits = []
        for r in self.relay_metadata:
            flags = r.get('flags', [])
            if not isinstance(flags, (list, tuple)):
                continue
            if 'Exit' in flags:
                exits.append(r)
        return exits
    
    def get_relay_by_ip(self, ip):
        """Find relay by IP address."""
        return [r for r in self.relay_metadata if r.get('ip') == ip]
    
    def get_relay_by_fingerprint(self, fingerprint):
        """Find relay by fingerprint."""
        for r in self.relay_metadata:
            if r.get('fingerprint') == fingerprint:
                return r
        return None
    
    def get_relays_by_country(self, country_code):
        """Get all relays in a specific country."""
        return [r for r in self.relay_metadata if r.get('country') == country_code]
    
    def get_high_bandwidth_relays(self, min_bandwidth=5000000):
        """Get relays with bandwidth above threshold (default 5MB/s)."""
        return [r for r in self.relay_metadata 
                if r.get('bandwidth', 0) >= min_bandwidth]
    
    def get_stable_guards(self, min_uptime=604800):
        """Get stable guard relays (default: 7 days uptime)."""
        guards = self.get_guard_relays()
        return [g for g in guards if g.get('uptime', 0) >= min_uptime]
    
    def get_consensus_summary(self):
        """Get summary statistics about the current consensus."""
        total = len(self.relay_metadata)
        guards = len(self.get_guard_relays())
        exits = len(self.get_exit_relays())
        countries = len(set(r.get('country', 'XX') for r in self.relay_metadata))
        avg_bandwidth = sum(r.get('bandwidth', 0) for r in self.relay_metadata) / max(1, total)
        
        return {
            'total_relays': total,
            'guard_relays': guards,
            'exit_relays': exits,
            'countries_represented': countries,
            'avg_bandwidth': avg_bandwidth,
            'api_status': self.api_health_status['status'],
            'cache_age_seconds': (datetime.now() - self.last_fetch).total_seconds() if self.last_fetch else None
        }
    
    def _get_country_coordinates(self, country_code):
        """Get approximate center coordinates for a country code.
        
        Returns tuple (latitude, longitude) or (None, None) if not found.
        """
        # Approximate country center coordinates for common Tor relay countries
        country_coords = {
            'US': (37.0902, -95.7129),
            'DE': (51.1657, 10.4515),
            'FR': (46.2276, 2.2137),
            'NL': (52.1326, 5.2913),
            'GB': (55.3781, -3.4360),
            'SE': (60.1282, 18.6435),
            'CA': (56.1304, -106.3468),
            'CH': (46.8182, 8.2275),
            'RO': (45.9432, 24.9668),
            'FI': (61.9241, 25.7482),
            'RU': (61.5240, 105.3188),
            'UA': (48.3794, 31.1656),
            'PL': (51.9194, 19.1451),
            'IT': (41.8719, 12.5674),
            'ES': (40.4637, -3.7492),
            'AT': (47.5162, 14.5501),
            'CZ': (49.8175, 15.4730),
            'NO': (60.4720, 8.4689),
            'DK': (56.2639, 9.5018),
            'BE': (50.5039, 4.4699),
            'JP': (36.2048, 138.2529),
            'SG': (1.3521, 103.8198),
            'AU': (-25.2744, 133.7751),
            'BR': (-14.2350, -51.9253),
            'IN': (20.5937, 78.9629),
            'CN': (35.8617, 104.1954),
            'KR': (35.9078, 127.7669),
            'MX': (23.6345, -102.5528),
            'AR': (-38.4161, -63.6167),
            'ZA': (-30.5595, 22.9375),
        }
        
        return country_coords.get(country_code.upper(), (None, None))
    
    def _get_ip_geolocation(self, ip_address: str) -> dict:
        """Fetch geolocation data for an IP address using ip-api.com.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dictionary with country, city, region, lat, lon, as, isp
        """
        try:
            # Use ip-api.com free tier (45 requests/minute)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=3,
                headers=self.headers
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country_code': data.get('countryCode', 'XX'),
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'as_number': data.get('as', '').split()[0].replace('AS', '') if data.get('as') else None,
                        'as_name': ' '.join(data.get('as', '').split()[1:]) if data.get('as') else None,
                        'isp': data.get('isp')
                    }
        except Exception as e:
            # Silently fail and return defaults
            pass
        
        return {
            'country_code': 'XX',
            'country': 'Unknown',
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'as_number': None,
            'as_name': None,
            'isp': None
        }
    
    def _get_country_name(self, country_code: str) -> str:
        """Convert ISO 3166-1 alpha-2 country code to full country name.
        
        Args:
            country_code: Two-letter ISO country code (e.g., 'US', 'DE', 'FR')
            
        Returns:
            Full country name or the country code if not found
        """
        # Comprehensive ISO 3166-1 alpha-2 country code mapping
        country_map = {
            'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany',
            'FR': 'France', 'NL': 'Netherlands', 'SE': 'Sweden', 'CH': 'Switzerland',
            'CA': 'Canada', 'AU': 'Australia', 'JP': 'Japan', 'KR': 'South Korea',
            'SG': 'Singapore', 'HK': 'Hong Kong', 'IN': 'India', 'BR': 'Brazil',
            'RU': 'Russia', 'CN': 'China', 'IT': 'Italy', 'ES': 'Spain',
            'NO': 'Norway', 'DK': 'Denmark', 'FI': 'Finland', 'PL': 'Poland',
            'CZ': 'Czech Republic', 'AT': 'Austria', 'BE': 'Belgium', 'IE': 'Ireland',
            'RO': 'Romania', 'UA': 'Ukraine', 'IL': 'Israel', 'TR': 'Turkey',
            'MX': 'Mexico', 'AR': 'Argentina', 'CL': 'Chile', 'ZA': 'South Africa',
            'NG': 'Nigeria', 'EG': 'Egypt', 'TH': 'Thailand', 'MY': 'Malaysia',
            'ID': 'Indonesia', 'PH': 'Philippines', 'VN': 'Vietnam', 'BD': 'Bangladesh',
            'PK': 'Pakistan', 'IR': 'Iran', 'IQ': 'Iraq', 'SA': 'Saudi Arabia',
            'AE': 'United Arab Emirates', 'NZ': 'New Zealand', 'GR': 'Greece', 'PT': 'Portugal',
            'HU': 'Hungary', 'BG': 'Bulgaria', 'HR': 'Croatia', 'RS': 'Serbia',
            'SK': 'Slovakia', 'SI': 'Slovenia', 'LT': 'Lithuania', 'LV': 'Latvia',
            'EE': 'Estonia', 'LU': 'Luxembourg', 'CY': 'Cyprus', 'MT': 'Malta',
            'IS': 'Iceland', 'MD': 'Moldova', 'BY': 'Belarus', 'GE': 'Georgia',
            'AM': 'Armenia', 'AZ': 'Azerbaijan', 'KZ': 'Kazakhstan', 'UZ': 'Uzbekistan',
            'KE': 'Kenya', 'GH': 'Ghana', 'TZ': 'Tanzania', 'UG': 'Uganda',
            'CO': 'Colombia', 'VE': 'Venezuela', 'PE': 'Peru', 'EC': 'Ecuador',
            'BO': 'Bolivia', 'PY': 'Paraguay', 'UY': 'Uruguay', 'CR': 'Costa Rica',
            'PA': 'Panama', 'GT': 'Guatemala', 'CU': 'Cuba', 'DO': 'Dominican Republic',
            'PR': 'Puerto Rico', 'JM': 'Jamaica', 'TT': 'Trinidad and Tobago',
            'KP': 'North Korea', 'MM': 'Myanmar', 'KH': 'Cambodia', 'LA': 'Laos',
            'NP': 'Nepal', 'LK': 'Sri Lanka', 'AF': 'Afghanistan', 'KW': 'Kuwait',
            'OM': 'Oman', 'QA': 'Qatar', 'BH': 'Bahrain', 'JO': 'Jordan', 'LB': 'Lebanon',
            'SY': 'Syria', 'YE': 'Yemen', 'DZ': 'Algeria', 'MA': 'Morocco', 'TN': 'Tunisia',
            'LY': 'Libya', 'SD': 'Sudan', 'ET': 'Ethiopia', 'AO': 'Angola', 'MZ': 'Mozambique',
            'ZW': 'Zimbabwe', 'ZM': 'Zambia', 'BW': 'Botswana', 'NA': 'Namibia',
            'MU': 'Mauritius', 'MG': 'Madagascar', 'CI': 'Ivory Coast', 'SN': 'Senegal',
            'CM': 'Cameroon', 'CD': 'DR Congo', 'MW': 'Malawi', 'BF': 'Burkina Faso',
            'ML': 'Mali', 'NE': 'Niger', 'TD': 'Chad', 'SO': 'Somalia', 'RW': 'Rwanda',
            'BI': 'Burundi', 'DJ': 'Djibouti', 'ER': 'Eritrea', 'SS': 'South Sudan',
            'GA': 'Gabon', 'CG': 'Congo', 'CF': 'Central African Republic', 'GQ': 'Equatorial Guinea',
            'ST': 'Sao Tome and Principe', 'SC': 'Seychelles', 'KM': 'Comoros', 'CV': 'Cape Verde',
            'GW': 'Guinea-Bissau', 'GN': 'Guinea', 'SL': 'Sierra Leone', 'LR': 'Liberia',
            'TG': 'Togo', 'BJ': 'Benin', 'MR': 'Mauritania', 'GM': 'Gambia',
            'AL': 'Albania', 'BA': 'Bosnia and Herzegovina', 'MK': 'North Macedonia', 'ME': 'Montenegro',
            'XK': 'Kosovo', 'SM': 'San Marino', 'VA': 'Vatican City', 'MC': 'Monaco',
            'LI': 'Liechtenstein', 'AD': 'Andorra', 'GI': 'Gibraltar', 'IM': 'Isle of Man',
            'JE': 'Jersey', 'GG': 'Guernsey', 'FO': 'Faroe Islands', 'GL': 'Greenland',
            'AX': 'Aland Islands', 'SJ': 'Svalbard and Jan Mayen', 'BV': 'Bouvet Island',
            'HM': 'Heard Island and McDonald Islands', 'GS': 'South Georgia', 'TF': 'French Southern Territories',
            'AQ': 'Antarctica', 'BQ': 'Caribbean Netherlands', 'CW': 'Curacao', 'SX': 'Sint Maarten',
            'MF': 'Saint Martin', 'BL': 'Saint Barthelemy', 'PM': 'Saint Pierre and Miquelon',
            'WF': 'Wallis and Futuna', 'PF': 'French Polynesia', 'NC': 'New Caledonia',
            'VU': 'Vanuatu', 'FJ': 'Fiji', 'PG': 'Papua New Guinea', 'SB': 'Solomon Islands',
            'TV': 'Tuvalu', 'NR': 'Nauru', 'KI': 'Kiribati', 'MH': 'Marshall Islands',
            'FM': 'Micronesia', 'PW': 'Palau', 'WS': 'Samoa', 'TO': 'Tonga',
            'CK': 'Cook Islands', 'NU': 'Niue', 'TK': 'Tokelau', 'PN': 'Pitcairn Islands',
            'BN': 'Brunei', 'TL': 'East Timor', 'MN': 'Mongolia', 'BT': 'Bhutan',
            'MV': 'Maldives', 'TM': 'Turkmenistan', 'TJ': 'Tajikistan', 'KG': 'Kyrgyzstan'
        }
        
        if not country_code or country_code.upper() == 'UNKNOWN':
            return 'Unknown'
        
        return country_map.get(country_code.upper(), country_code.upper())

    def store_metadata(self, path="relay_metadata.json"):
        """Persist the parsed relay metadata."""
        with open(path, "w") as handle:
            json.dump(self.relay_metadata, handle, indent=4)
    
    def _generate_fallback_data(self):
        """Generate realistic fallback data when Onionoo API is unavailable (for demo/hackathon)."""
        import random
        
        countries = ['US', 'DE', 'FR', 'NL', 'GB', 'SE', 'CA', 'CH', 'RO', 'FI']
        flags_options = [
            ['Guard', 'Fast', 'Running', 'Stable', 'Valid'],
            ['Exit', 'Fast', 'Running', 'Stable', 'Valid'],
            ['Guard', 'Exit', 'Fast', 'Running', 'Stable', 'Valid', 'HSDir'],
            ['Fast', 'Running', 'Stable', 'Valid']
        ]
        
        relays = []
        for i in range(100):
            fingerprint = ''.join(random.choices('0123456789ABCDEF', k=40))
            flags = random.choice(flags_options)
            relays.append({
                'n': f"TorRelay{i}",
                'f': fingerprint,
                'a': [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}:{random.randint(9000,9999)}"],
                'r': flags,
                'c': random.choice(countries),
            })
        
        print("📌 Using fallback demo relay data (Onionoo API unavailable)")
        return {'relays': relays, 'version': '9.0', 'relays_published': datetime.now().isoformat()}
