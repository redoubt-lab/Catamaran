#!/usr/bin/env python3
import sqlite3
import csv

db_path = ''
csv_file = ''

def extract_libpackage(caller):
    if caller.startswith("<") and ":" in caller:
        caller = caller.lstrip("<")
        package_part = caller.split(":", 1)[0]
    else:
        package_part = caller

    if "." in package_part:
        libpackage = package_part.rsplit(".", 1)[0]
    else:
        libpackage = package_part

    return libpackage

def main(db_path, csv_output):
    exclude_list = [
        "c",
        "e",
        "e.w"
    ]
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    sql = """
    SELECT out.caller, res.pii_type, apk
    FROM possible_output out 
    LEFT JOIN final_result res 
      ON res.content = out.content 
    WHERE res.content IS NOT NULL
    """
    cur.execute(sql)
    rows = cur.fetchall()

    libpackage_data = {}
    for row in rows:
        caller, pii_type, apk = row
        libpackage = extract_libpackage(caller)
        if libpackage not in libpackage_data:
            libpackage_data[libpackage] = {"apks": set(), "pii_types": set()}
        libpackage_data[libpackage]["apks"].add(apk)
        libpackage_data[libpackage]["pii_types"].add(pii_type)

    result_list = []
    for libpackage, info in libpackage_data.items():
        if libpackage in exclude_list:
            continue
        apk_number = len(info["apks"])
        if apk_number >= 2:
            pii_type_str = ",".join(sorted(info["pii_types"]))
            result_list.append((libpackage, apk_number, pii_type_str))
    
    result_list.sort(key=lambda x: x[1], reverse=True)

    header = f"{'libpackage':<30} {'apk number':<12} {'pii type'}"
    print(header)
    print("-" * len(header))
    for libpackage, apk_number, pii_type_str in result_list:
        print(f"{libpackage:<30} {apk_number:<12} {pii_type_str}")

    try:
        with open(csv_output, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['libpackage', 'apk number', 'pii type'])
            csv_writer.writerows(result_list)
    except Exception as e:
        print(e)

    conn.close()

if __name__ == "__main__":
    main(db_path, csv_file)