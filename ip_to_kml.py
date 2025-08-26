"""
Script: ip_to_kml
Desc: creates a kml file with the geographical data for the dest IP
Author: Turaki Annan 09/12/2024
"""

import geoip2.database
import simplekml


def fetch_geolocation(ip, reader):
    """
    Uses geopip2 database to get the geographical data of given IP

    args: the IP of the address to be geolacter and the r
    eader to read the geo database

    Returns: Geolocation details.
    """
    try:
        response = reader.city(ip)
        return {
            "city": response.city.name or "Unknown",
            "country": response.country.name or "Unknown",
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
    except geoip2.errors.AddressNotFoundError:
        print(f"IP {ip} not found in database")
    return None


def create_kml(ip_pairs, geoip_db_path="GeoLite2-City.mmdb",
               output_file="geolocations.kml"):
    """
    make a kml file for unique dest IPs

    Args:
    ip_pairs dictionary of ips
    geoip_db_path is the path to the GeoIP database
    output_file where the kml files will be saved to

    """
    kml = simplekml.Kml()
    unique_dest_ips = {dst for _, dst in ip_pairs.keys()}

    with geoip2.database.Reader(geoip_db_path) as reader:
        for dst_ip in unique_dest_ips:
            geo_info = fetch_geolocation(dst_ip, reader)
            if geo_info and geo_info["latitude"] and geo_info["longitude"]:
                # counts total packets to the dest IP
                packet_count = sum(
                    counts['A_to_B']
                    for (src, dst), counts in ip_pairs.items()
                    if dst == dst_ip
                )
                description = (
                    f"Packet Count: {packet_count}\n"
                    f"City: {geo_info['city']}\n"
                    f"Country: {geo_info['country']}"
                )

                # Adding point to kml file
                kml.newpoint(
                    name=dst_ip,
                    coords=[(geo_info["longitude"], geo_info["latitude"])],
                    description=description,
                )

    # Saving the KML file
    kml.save(output_file)
    print(f"KML file saved as {output_file}")
