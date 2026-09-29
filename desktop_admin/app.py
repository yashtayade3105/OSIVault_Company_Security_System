"""
OSIVault Native Desktop Admin Application Launcher.
Uses PyWebView to launch a native Windows Desktop GUI Application window.
Includes real-time PostgreSQL database connector, live auto-sync telemetry engine, and multi-format data export engine.
"""

import os
import sys
import json
import csv
import io
import datetime
import decimal
import uuid
import html
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import psycopg2

ACTIVE_DB_CONFIG = {
    "engine": "postgresql",
    "host": "127.0.0.1",
    "port": 5433,
    "dbname": "Test_Project1DB",
    "user": "postgres",
    "password": "[REDACTED]",
    "sslmode": "disable"
}


class PostgresJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for PostgreSQL data types (datetime, decimal, uuid, bytes)."""
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        elif isinstance(obj, decimal.Decimal):
            return float(obj)
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, bytes):
            return obj.hex()
        try:
            return super().default(obj)
        except Exception:
            return str(obj)


def resolve_ui_dir():
    """Dynamically resolve the UI directory path for both source Python mode and PyInstaller executable mode."""
    if getattr(sys, 'frozen', False):
        # Bundled PyInstaller executable mode
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(sys.executable)))
    else:
        # Source Python script mode
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    candidates = [
        os.path.join(base_dir, "desktop_admin", "ui"),
        os.path.join(base_dir, "ui"),
        os.path.join(os.getcwd(), "desktop_admin", "ui"),
        os.path.join(os.getcwd(), "ui"),
    ]
    for path in candidates:
        if os.path.isdir(path) and os.path.exists(os.path.join(path, "index.html")):
            return path
    
    return base_dir


UI_DIR = resolve_ui_dir()


def format_export_data(table_name, columns, rows, fmt):
    """Format table data into requested format: csv, xlsx_xml, json, sql, tsv, html."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"{table_name}_{timestamp}"

    if fmt == "json":
        filename = f"{base_filename}.json"
        content = json.dumps(rows, cls=PostgresJSONEncoder, indent=2)
        mime = "application/json"

    elif fmt == "csv":
        filename = f"{base_filename}.csv"
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(columns)
        for r in rows:
            writer.writerow([r.get(c) for c in columns])
        content = output.getvalue()
        mime = "text/csv"

    elif fmt == "tsv":
        filename = f"{base_filename}.tsv"
        output = io.StringIO()
        writer = csv.writer(output, delimiter='\t')
        writer.writerow(columns)
        for r in rows:
            writer.writerow([r.get(c) for c in columns])
        content = output.getvalue()
        mime = "text/tab-separated-values"

    elif fmt == "sql":
        filename = f"{base_filename}.sql"
        lines = [
            f"-- OSIVault Enterprise SQL Data Dump",
            f"-- Table: {table_name}",
            f"-- Total Records: {len(rows)}",
            f"-- Timestamp: {datetime.datetime.now().isoformat()}",
            ""
        ]
        col_list = ", ".join([f'"{c}"' for c in columns])
        for r in rows:
            vals = []
            for c in columns:
                v = r.get(c)
                if v is None:
                    vals.append("NULL")
                elif isinstance(v, (int, float, decimal.Decimal)):
                    vals.append(str(v))
                elif isinstance(v, bool):
                    vals.append("TRUE" if v else "FALSE")
                else:
                    escaped = str(v).replace("'", "''")
                    vals.append(f"'{escaped}'")
            lines.append(f'INSERT INTO "{table_name}" ({col_list}) VALUES ({", ".join(vals)});')
        content = "\n".join(lines)
        mime = "application/sql"

    elif fmt == "xlsx_xml":
        filename = f"{base_filename}.xls"
        # Generate Microsoft Excel XML Spreadsheet format
        xml_lines = [
            '<?xml version="1.0"?>',
            '<?mso-application progid="Excel.Sheet"?>',
            '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"',
            ' xmlns:o="urn:schemas-microsoft-com:office:office"',
            ' xmlns:x="urn:schemas-microsoft-com:office:excel"',
            ' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"',
            ' xmlns:html="http://www.w3.org/TR/REC-html40">',
            ' <Styles>',
            '  <Style ss:ID="HeaderStyle">',
            '   <Font ss:Bold="1" ss:Color="#FFFFFF" ss:Size="11" ss:FontName="Calibri"/>',
            '   <Interior ss:Color="#10B981" ss:Pattern="Solid"/>',
            '   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>',
            '  </Style>',
            '  <Style ss:ID="DataStyle">',
            '   <Font ss:Color="#000000" ss:Size="10" ss:FontName="Calibri"/>',
            '  </Style>',
            ' </Styles>',
            f' <Worksheet ss:Name="{table_name[:30]}">',
            '  <Table>',
            '   <Row ss:StyleID="HeaderStyle" ss:Height="24">'
        ]
        for c in columns:
            xml_lines.append(f'    <Cell><Data ss:Type="String">{html.escape(c)}</Data></Cell>')
        xml_lines.append('   </Row>')

        for r in rows:
            xml_lines.append('   <Row ss:StyleID="DataStyle" ss:Height="20">')
            for c in columns:
                v = r.get(c)
                if v is None:
                    xml_lines.append('    <Cell><Data ss:Type="String"></Data></Cell>')
                elif isinstance(v, (int, float, decimal.Decimal)):
                    xml_lines.append(f'    <Cell><Data ss:Type="Number">{v}</Data></Cell>')
                else:
                    xml_lines.append(f'    <Cell><Data ss:Type="String">{html.escape(str(v))}</Data></Cell>')
            xml_lines.append('   </Row>')

        xml_lines.extend([
            '  </Table>',
            ' </Worksheet>',
            '</Workbook>'
        ])
        content = "\n".join(xml_lines)
        mime = "application/vnd.ms-excel"

    elif fmt == "html":
        filename = f"{base_filename}.html"
        rows_html = []
        for r in rows:
            tds = "".join([f'<td style="padding: 10px; border: 1px solid #334155; font-family: monospace;">{html.escape(str(r.get(c, "")))}</td>' for c in columns])
            rows_html.append(f'<tr style="background: #0f172a;">{tds}</tr>')
        
        ths = "".join([f'<th style="padding: 12px; background: #10b981; color: white; border: 1px solid #059669; font-family: monospace; text-align: left;">{html.escape(c)}</th>' for c in columns])
        content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>OSIVault Export - {table_name}</title>
  <style>
    body {{ font-family: 'Plus Jakarta Sans', system-ui, sans-serif; background: #080c14; color: #f8fafc; padding: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
    h2 {{ color: #10b981; font-size: 24px; font-weight: 800; }}
    .badge {{ background: rgba(16,185,129,0.2); color: #34d399; padding: 4px 12px; border-radius: 9999px; font-weight: bold; border: 1px solid rgba(16,185,129,0.4); font-size: 11px; }}
  </style>
</head>
<body>
  <h2>OSIVault Enterprise Data Export</h2>
  <div style="margin-bottom: 10px;">
    <span class="badge">Table: {table_name}</span>
    <span class="badge" style="background: rgba(6,182,212,0.2); color: #67e8f9; border-color: rgba(6,182,212,0.4);">Records: {len(rows)}</span>
    <span class="badge" style="background: rgba(168,85,247,0.2); color: #c084fc; border-color: rgba(168,85,247,0.4);">Exported: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
  </div>
  <table>
    <thead><tr>{ths}</tr></thead>
    <tbody>{"".join(rows_html)}</tbody>
  </table>
</body>
</html>"""
        mime = "text/html"

    else:
        raise ValueError(f"Unsupported format: {fmt}")

    return {
        "success": True,
        "filename": filename,
        "content": content,
        "mime_type": mime,
        "record_count": len(rows),
        "format": fmt
    }


class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def log_message(self, format, *args):
        # Suppress HTTP server stdout logs for clean desktop execution
        pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def do_POST(self):
        """Handle real-time PostgreSQL database API requests & live sync endpoints."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            payload = json.loads(post_data.decode('utf-8'))
        except Exception:
            payload = {}

        response = {"success": False, "error": "Unknown API endpoint"}

        if self.path == '/api/connect_db':
            response = self.handle_connect_db(payload)
        elif self.path == '/api/get_table_data':
            response = self.handle_get_table_data(payload)
        elif self.path == '/api/execute_sql':
            response = self.handle_execute_sql(payload)
        elif self.path == '/api/list_databases':
            response = self.handle_list_databases(payload)
        elif self.path == '/api/sync_status':
            response = self.handle_sync_status(payload)
        elif self.path == '/api/export_table_data':
            response = self.handle_export_table_data(payload)
        elif self.path == '/api/verify_admin_password':
            response = self.handle_verify_admin_password(payload)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response, cls=PostgresJSONEncoder).encode('utf-8'))

    def handle_connect_db(self, payload):
        global ACTIVE_DB_CONFIG
        host = payload.get("host", "127.0.0.1")
        port = int(payload.get("port", 5433))
        dbname = payload.get("dbname", "PublisherAgentDB_OSIVAULT")
        user = payload.get("user", "postgres")
        password = payload.get("password", "[REDACTED]")
        sslmode = payload.get("sslmode", "disable")

        try:
            try:
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    dbname=dbname,
                    user=user,
                    password=password,
                    sslmode=sslmode,
                    connect_timeout=5
                )
            except Exception as conn_err:
                if "ssl" in str(conn_err).lower() or sslmode == "disable":
                    # Smart auto-fallback for AWS RDS / Cloud DBs enforcing SSL/TLS
                    sslmode = "prefer"
                    conn = psycopg2.connect(
                        host=host,
                        port=port,
                        dbname=dbname,
                        user=user,
                        password=password,
                        sslmode="prefer",
                        connect_timeout=5
                    )
                else:
                    raise conn_err
            cur = conn.cursor()
            
            # Fetch all user tables from the specified database
            query = """
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema') 
                  AND table_type = 'BASE TABLE'
                ORDER BY table_name;
            """
            cur.execute(query)
            tables = [row[0] for row in cur.fetchall()]

            # Fast & exact row count lookup (checks pg_class estimate first, falls back to COUNT(*) if unanalyzed or 0)
            table_counts = {}
            try:
                cur.execute("""
                    SELECT c.relname, GREATEST(c.reltuples::bigint, 0)
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relkind = 'r';
                """)
                estimates = dict(cur.fetchall())
                for t in tables:
                    cnt = estimates.get(t, 0)
                    if cnt == 0:
                        try:
                            cur.execute(f'SELECT COUNT(*) FROM "{t}";')
                            res = cur.fetchone()
                            cnt = res[0] if res else 0
                        except Exception:
                            cnt = 0
                    table_counts[t] = cnt
            except Exception:
                for t in tables:
                    try:
                        cur.execute(f'SELECT COUNT(*) FROM "{t}";')
                        res = cur.fetchone()
                        table_counts[t] = res[0] if res else 0
                    except Exception:
                        table_counts[t] = 0

            conn.close()

            # Save active configuration
            ACTIVE_DB_CONFIG = {
                "engine": "postgresql",
                "host": host,
                "port": port,
                "dbname": dbname,
                "user": user,
                "password": password,
                "sslmode": sslmode
            }

            return {
                "success": True,
                "dbname": dbname,
                "host": host,
                "port": port,
                "user": user,
                "tables": tables,
                "table_counts": table_counts,
                "total_tables": len(tables),
                "message": f"Connected to PostgreSQL database '{dbname}'! Synced {len(tables)} tables."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_sync_status(self, payload):
        try:
            conn = psycopg2.connect(
                host=ACTIVE_DB_CONFIG["host"],
                port=int(ACTIVE_DB_CONFIG["port"]),
                dbname=ACTIVE_DB_CONFIG["dbname"],
                user=ACTIVE_DB_CONFIG["user"],
                password=ACTIVE_DB_CONFIG["password"],
                sslmode=ACTIVE_DB_CONFIG["sslmode"],
                connect_timeout=5
            )
            cur = conn.cursor()

            query = """
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema') 
                  AND table_type = 'BASE TABLE'
                ORDER BY table_name;
            """
            cur.execute(query)
            tables = [row[0] for row in cur.fetchall()]

            # Fast & exact row count lookup (checks pg_class estimate first, falls back to COUNT(*) if unanalyzed or 0)
            table_counts = {}
            try:
                cur.execute("""
                    SELECT c.relname, GREATEST(c.reltuples::bigint, 0)
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relkind = 'r';
                """)
                estimates = dict(cur.fetchall())
                for t in tables:
                    cnt = estimates.get(t, 0)
                    if cnt == 0:
                        try:
                            cur.execute(f'SELECT COUNT(*) FROM "{t}";')
                            res = cur.fetchone()
                            cnt = res[0] if res else 0
                        except Exception:
                            cnt = 0
                    table_counts[t] = cnt
            except Exception:
                for t in tables:
                    try:
                        cur.execute(f'SELECT COUNT(*) FROM "{t}";')
                        res = cur.fetchone()
                        table_counts[t] = res[0] if res else 0
                    except Exception:
                        table_counts[t] = 0

            conn.close()

            return {
                "success": True,
                "dbname": ACTIVE_DB_CONFIG["dbname"],
                "host": ACTIVE_DB_CONFIG["host"],
                "port": ACTIVE_DB_CONFIG["port"],
                "user": ACTIVE_DB_CONFIG["user"],
                "tables": tables,
                "table_counts": table_counts,
                "total_tables": len(tables),
                "timestamp": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_get_table_data(self, payload):
        table_name = payload.get("tableName")
        if not table_name:
            return {"success": False, "error": "Table name is required"}

        # Safe limit enforcement for UI display to prevent memory/fetch crashes on large tables
        raw_limit = int(payload.get("limit", 100))
        if raw_limit <= 0 or raw_limit > 1000:
            limit = 500  # Cap UI display limit at 500 rows per page max
        else:
            limit = raw_limit

        offset = int(payload.get("offset", 0))
        if offset < 0:
            offset = 0

        search = str(payload.get("search", "")).strip()
        start_date = str(payload.get("startDate", "")).strip()
        end_date = str(payload.get("endDate", "")).strip()
        date_column = str(payload.get("dateColumn", "")).strip()

        try:
            conn = psycopg2.connect(
                host=ACTIVE_DB_CONFIG["host"],
                port=int(ACTIVE_DB_CONFIG["port"]),
                dbname=ACTIVE_DB_CONFIG["dbname"],
                user=ACTIVE_DB_CONFIG["user"],
                password=ACTIVE_DB_CONFIG["password"],
                sslmode=ACTIVE_DB_CONFIG["sslmode"],
                connect_timeout=5
            )
            cur = conn.cursor()

            quoted_table = f'"{table_name}"'
            
            # Fetch table columns & data types
            cur.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema') 
                  AND table_name = %s 
                ORDER BY ordinal_position;
            """, (table_name,))
            col_info = cur.fetchall()
            columns = [c[0] for c in col_info]
            date_cols = [c[0] for c in col_info if any(t in c[1].lower() for t in ['date', 'time', 'timestamp'])]

            # Build dynamic WHERE clause
            where_clauses = []
            params = []

            # Global search across columns
            if search and columns:
                search_conds = []
                for col in columns[:15]:  # Search first 15 columns for performance
                    search_conds.append(f'"{col}"::text ILIKE %s')
                    params.append(f'%{search}%')
                where_clauses.append(f"({' OR '.join(search_conds)})")

            # Date Range Filter
            target_date_col = date_column if date_column in columns else (date_cols[0] if date_cols else None)
            if target_date_col:
                if start_date:
                    where_clauses.append(f'"{target_date_col}"::date >= %s::date')
                    params.append(start_date)
                if end_date:
                    where_clauses.append(f'"{target_date_col}"::date <= %s::date')
                    params.append(end_date)

            where_str = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            # Calculate total filtered rows
            if where_str:
                cur.execute(f'SELECT COUNT(*) FROM {quoted_table}{where_str};', params)
                total_rows = cur.fetchone()[0]
            else:
                # Fast row count estimation for unfiltered query
                try:
                    cur.execute("""
                        SELECT GREATEST(c.reltuples::bigint, 0)
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relname = %s;
                    """, (table_name,))
                    res = cur.fetchone()
                    total_rows = res[0] if res and res[0] > 0 else 0
                    if total_rows == 0:
                        cur.execute(f'SELECT COUNT(*) FROM {quoted_table};')
                        total_rows = cur.fetchone()[0]
                except Exception:
                    total_rows = 0

            # Execute paginated query with filters
            query_sql = f'SELECT * FROM {quoted_table}{where_str} LIMIT %s OFFSET %s;'
            cur.execute(query_sql, params + [limit, offset])

            raw_rows = cur.fetchall()

            rows = []
            for r in raw_rows:
                row_dict = {}
                for col, val in zip(columns, r):
                    row_dict[col] = val
                rows.append(row_dict)

            conn.close()

            return {
                "success": True,
                "tableName": table_name,
                "columns": columns,
                "dateColumns": date_cols,
                "rows": rows,
                "total_rows": total_rows,
                "offset": offset,
                "limit": limit,
                "search": search,
                "startDate": start_date,
                "endDate": end_date,
                "activeDateColumn": target_date_col
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_export_table_data(self, payload):
        table_name = payload.get("tableName")
        fmt = payload.get("format", "csv").lower()
        export_all = payload.get("exportAll", True)
        limit = int(payload.get("limit", 5000))
        is_preview = payload.get("isPreview", False)

        if not table_name:
            return {"success": False, "error": "Table name is required"}

        try:
            conn = psycopg2.connect(
                host=ACTIVE_DB_CONFIG["host"],
                port=int(ACTIVE_DB_CONFIG["port"]),
                dbname=ACTIVE_DB_CONFIG["dbname"],
                user=ACTIVE_DB_CONFIG["user"],
                password=ACTIVE_DB_CONFIG["password"],
                sslmode=ACTIVE_DB_CONFIG["sslmode"],
                connect_timeout=5
            )
            quoted_table = f'"{table_name}"'

            # Fast preview mode: fetch a small sample (50 rows) for modal display
            if is_preview:
                cur = conn.cursor()
                preview_limit = 50
                cur.execute(f'SELECT * FROM {quoted_table} LIMIT %s;', (preview_limit,))
                columns = [desc[0] for desc in cur.description] if cur.description else []
                raw_rows = cur.fetchall()
                rows = [dict(zip(columns, r)) for r in raw_rows]
                
                # Fetch total table count for display in preview modal
                try:
                    cur.execute(f'SELECT COUNT(*) FROM {quoted_table};')
                    count_row = cur.fetchone()
                    total_table_count = count_row[0] if count_row else len(rows)
                except Exception:
                    total_table_count = len(rows)
                conn.close()

                export_res = format_export_data(table_name, columns, rows, fmt)
                export_res["record_count"] = total_table_count
                return export_res

            # High-performance streaming export mode: stream rows in 10,000 batch chunks directly to disk file in Downloads
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"{table_name}_{timestamp}"

            ext_map = {
                "csv": "csv",
                "tsv": "tsv",
                "sql": "sql",
                "json": "json",
                "xlsx_xml": "xls",
                "html": "html"
            }
            mime_map = {
                "csv": "text/csv",
                "tsv": "text/tab-separated-values",
                "sql": "application/sql",
                "json": "application/json",
                "xlsx_xml": "application/vnd.ms-excel",
                "html": "text/html"
            }

            ext = ext_map.get(fmt, "csv")
            mime = mime_map.get(fmt, "text/csv")
            filename = f"{base_filename}.{ext}"

            downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(downloads_dir, exist_ok=True)
            file_path = os.path.join(downloads_dir, filename)

            # Use server-side named cursor to stream large datasets without high memory usage
            cursor_name = f"export_{uuid.uuid4().hex}"
            try:
                cur = conn.cursor(name=cursor_name)
                cur.itersize = 10000
                if export_all:
                    cur.execute(f'SELECT * FROM {quoted_table};')
                else:
                    cur.execute(f'SELECT * FROM {quoted_table} LIMIT %s;', (limit,))
            except Exception:
                cur = conn.cursor()
                if export_all:
                    cur.execute(f'SELECT * FROM {quoted_table};')
                else:
                    cur.execute(f'SELECT * FROM {quoted_table} LIMIT %s;', (limit,))

            columns = [desc[0] for desc in cur.description] if cur.description else []
            total_exported = 0

            with open(file_path, "w", encoding="utf-8") as f:
                if fmt == "csv":
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    while True:
                        batch = cur.fetchmany(10000)
                        if not batch:
                            break
                        writer.writerows(batch)
                        total_exported += len(batch)

                elif fmt == "tsv":
                    writer = csv.writer(f, delimiter='\t')
                    writer.writerow(columns)
                    while True:
                        batch = cur.fetchmany(10000)
                        if not batch:
                            break
                        writer.writerows(batch)
                        total_exported += len(batch)

                elif fmt == "sql":
                    f.write(f"-- OSIVault Enterprise SQL Data Dump\n")
                    f.write(f"-- Table: {table_name}\n")
                    f.write(f"-- Timestamp: {datetime.datetime.now().isoformat()}\n\n")
                    col_list = ", ".join([f'"{c}"' for c in columns])
                    while True:
                        batch = cur.fetchmany(5000)
                        if not batch:
                            break
                        lines = []
                        for r in batch:
                            vals = []
                            for v in r:
                                if v is None:
                                    vals.append("NULL")
                                elif isinstance(v, (int, float, decimal.Decimal)):
                                    vals.append(str(v))
                                elif isinstance(v, bool):
                                    vals.append("TRUE" if v else "FALSE")
                                else:
                                    escaped = str(v).replace("'", "''")
                                    vals.append(f"'{escaped}'")
                            lines.append(f'INSERT INTO "{table_name}" ({col_list}) VALUES ({", ".join(vals)});\n')
                        f.writelines(lines)
                        total_exported += len(batch)

                elif fmt == "json":
                    f.write("[\n")
                    encoder = PostgresJSONEncoder()
                    first = True
                    while True:
                        batch = cur.fetchmany(5000)
                        if not batch:
                            break
                        lines = []
                        for r in batch:
                            row_dict = dict(zip(columns, r))
                            encoded_row = encoder.encode(row_dict)
                            if not first:
                                lines.append(",\n" + encoded_row)
                            else:
                                lines.append(encoded_row)
                                first = False
                        f.writelines(lines)
                        total_exported += len(batch)
                    f.write("\n]")

                elif fmt == "xlsx_xml":
                    f.write('<?xml version="1.0"?>\n')
                    f.write('<?mso-application progid="Excel.Sheet"?>\n')
                    f.write('<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"\n')
                    f.write(' xmlns:o="urn:schemas-microsoft-com:office:office"\n')
                    f.write(' xmlns:x="urn:schemas-microsoft-com:office:excel"\n')
                    f.write(' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"\n')
                    f.write(' xmlns:html="http://www.w3.org/TR/REC-html40">\n')
                    f.write(' <Styles>\n')
                    f.write('  <Style ss:ID="HeaderStyle">\n')
                    f.write('   <Font ss:Bold="1" ss:Color="#FFFFFF" ss:Size="11" ss:FontName="Calibri"/>\n')
                    f.write('   <Interior ss:Color="#10B981" ss:Pattern="Solid"/>\n')
                    f.write('   <Alignment ss:Horizontal="Center" ss:Vertical="Center"/>\n')
                    f.write('  </Style>\n')
                    f.write('  <Style ss:ID="DataStyle">\n')
                    f.write('   <Font ss:Color="#000000" ss:Size="10" ss:FontName="Calibri"/>\n')
                    f.write('  </Style>\n')
                    f.write(' </Styles>\n')
                    f.write(f' <Worksheet ss:Name="{table_name[:30]}">\n')
                    f.write('  <Table>\n')
                    f.write('   <Row ss:StyleID="HeaderStyle" ss:Height="24">\n')
                    for c in columns:
                        f.write(f'    <Cell><Data ss:Type="String">{html.escape(c)}</Data></Cell>\n')
                    f.write('   </Row>\n')

                    while True:
                        batch = cur.fetchmany(5000)
                        if not batch:
                            break
                        xml_lines = []
                        for r in batch:
                            xml_lines.append('   <Row ss:StyleID="DataStyle" ss:Height="20">\n')
                            for v in r:
                                if v is None:
                                    xml_lines.append('    <Cell><Data ss:Type="String"></Data></Cell>\n')
                                elif isinstance(v, (int, float, decimal.Decimal)):
                                    xml_lines.append(f'    <Cell><Data ss:Type="Number">{v}</Data></Cell>\n')
                                else:
                                    xml_lines.append(f'    <Cell><Data ss:Type="String">{html.escape(str(v))}</Data></Cell>\n')
                            xml_lines.append('   </Row>\n')
                        f.writelines(xml_lines)
                        total_exported += len(batch)

                    f.write('  </Table>\n')
                    f.write(' </Worksheet>\n')
                    f.write('</Workbook>\n')

                elif fmt == "html":
                    f.write('<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n')
                    f.write(f'<title>OSIVault Export - {html.escape(table_name)}</title>\n')
                    f.write('<style>\nbody { font-family: monospace; background: #080c14; color: #f8fafc; padding: 24px; }\n')
                    f.write('table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }\n')
                    f.write('th { padding: 12px; background: #10b981; color: white; border: 1px solid #059669; text-align: left; }\n')
                    f.write('td { padding: 10px; border: 1px solid #334155; }\n</style>\n</head>\n<body>\n')
                    f.write(f'<h2>OSIVault Enterprise Data Export - {html.escape(table_name)}</h2>\n')
                    f.write('<table>\n<thead><tr>\n')
                    for c in columns:
                        f.write(f'<th>{html.escape(c)}</th>\n')
                    f.write('</tr></thead>\n<tbody>\n')

                    while True:
                        batch = cur.fetchmany(5000)
                        if not batch:
                            break
                        html_lines = []
                        for r in batch:
                            html_lines.append('<tr style="background: #0f172a;">')
                            for v in r:
                                val_str = html.escape(str(v)) if v is not None else ""
                                html_lines.append(f'<td>{val_str}</td>')
                            html_lines.append('</tr>\n')
                        f.writelines(html_lines)
                        total_exported += len(batch)

                    f.write('</tbody>\n</table>\n</body>\n</html>\n')

            conn.close()

            print(f"[EXPORT SUCCESS] Streamed {total_exported} rows directly to Downloads: {file_path}")

            return {
                "success": True,
                "filename": filename,
                "saved_path": file_path,
                "record_count": total_exported,
                "mime_type": mime,
                "content": ""
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_execute_sql(self, payload):
        query = payload.get("query", "").strip()
        if not query:
            return {"success": False, "error": "SQL query required"}

        try:
            conn = psycopg2.connect(
                host=ACTIVE_DB_CONFIG["host"],
                port=int(ACTIVE_DB_CONFIG["port"]),
                dbname=ACTIVE_DB_CONFIG["dbname"],
                user=ACTIVE_DB_CONFIG["user"],
                password=ACTIVE_DB_CONFIG["password"],
                sslmode=ACTIVE_DB_CONFIG["sslmode"],
                connect_timeout=5
            )
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(query)

            if cur.description:
                columns = [desc[0] for desc in cur.description]
                raw_rows = cur.fetchall()
                rows = [dict(zip(columns, r)) for r in raw_rows]
                row_count = len(rows)
            else:
                columns = []
                rows = []
                row_count = cur.rowcount

            conn.close()

            return {
                "success": True,
                "columns": columns,
                "rows": rows,
                "row_count": row_count
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_list_databases(self, payload):
        host = payload.get("host", ACTIVE_DB_CONFIG["host"])
        port = int(payload.get("port", ACTIVE_DB_CONFIG["port"]))
        user = payload.get("user", ACTIVE_DB_CONFIG["user"])
        password = payload.get("password", ACTIVE_DB_CONFIG["password"])
        sslmode = payload.get("sslmode", ACTIVE_DB_CONFIG["sslmode"])

        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname="postgres",
                user=user,
                password=password,
                sslmode=sslmode,
                connect_timeout=5
            )
            cur = conn.cursor()
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname;")
            databases = [r[0] for r in cur.fetchall()]
            conn.close()
            return {"success": True, "databases": databases}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_verify_admin_password(self, payload):
        email = payload.get("email", "").strip()
        password = payload.get("password", "")

        if not email or not password:
            return {"success": False, "error": "Work email address and password are required."}

        try:
            # Check active DB and auto-discover database containing osivault_admin_account table if needed
            target_dbname = ACTIVE_DB_CONFIG["dbname"]

            def check_table(dbname):
                try:
                    c = psycopg2.connect(
                        host=ACTIVE_DB_CONFIG["host"],
                        port=int(ACTIVE_DB_CONFIG["port"]),
                        dbname=dbname,
                        user=ACTIVE_DB_CONFIG["user"],
                        password=ACTIVE_DB_CONFIG["password"],
                        sslmode=ACTIVE_DB_CONFIG["sslmode"],
                        connect_timeout=3
                    )
                    cur_c = c.cursor()
                    cur_c.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'osivault_admin_account');")
                    has_tbl = cur_c.fetchone()[0]
                    c.close()
                    return has_tbl
                except Exception:
                    return False

            if not check_table(target_dbname):
                found_db = None
                candidate_dbs = ["Test_Project1DB", "PublisherAgentDB_OSIVAULT", "OSIVaultSystemDB"]
                for c_db in candidate_dbs:
                    if check_table(c_db):
                        found_db = c_db
                        break

                if not found_db:
                    try:
                        pg_conn = psycopg2.connect(
                            host=ACTIVE_DB_CONFIG["host"],
                            port=int(ACTIVE_DB_CONFIG["port"]),
                            dbname="postgres",
                            user=ACTIVE_DB_CONFIG["user"],
                            password=ACTIVE_DB_CONFIG["password"],
                            sslmode=ACTIVE_DB_CONFIG["sslmode"],
                            connect_timeout=3
                        )
                        cur_pg = pg_conn.cursor()
                        cur_pg.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
                        all_dbs = [r[0] for r in cur_pg.fetchall()]
                        pg_conn.close()
                        for adb in all_dbs:
                            if check_table(adb):
                                found_db = adb
                                break
                    except Exception:
                        pass

                if found_db:
                    ACTIVE_DB_CONFIG["dbname"] = found_db
                    target_dbname = found_db
                else:
                    return {
                        "success": False,
                        "error": f"Table 'osivault_admin_account' not found in database '{target_dbname}'. Run 'python manage.py createosivaultsuperuser' or 'python manage.py migrate' first."
                    }

            conn = psycopg2.connect(
                host=ACTIVE_DB_CONFIG["host"],
                port=int(ACTIVE_DB_CONFIG["port"]),
                dbname=target_dbname,
                user=ACTIVE_DB_CONFIG["user"],
                password=ACTIVE_DB_CONFIG["password"],
                sslmode=ACTIVE_DB_CONFIG["sslmode"],
                connect_timeout=5
            )
            cur = conn.cursor()

            cur.execute(
                "SELECT email, password_hash, role, is_active FROM osivault_admin_account WHERE LOWER(email) = LOWER(%s);",
                (email,)
            )
            row = cur.fetchone()
            conn.close()

            if not row:
                return {
                    "success": False,
                    "error": f"Invalid credentials. Account '{email}' does not exist in osivault_admin_account table. Create superuser via 'python manage.py createosivaultsuperuser'."
                }

            db_email, password_hash, role, is_active = row

            if not is_active:
                return {"success": False, "error": f"Account '{email}' is deactivated."}

            import django
            from django.conf import settings
            if not settings.configured:
                settings.configure(PASSWORD_HASHERS=[
                    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
                    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
                    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
                    'django.contrib.auth.hashers.Argon2PasswordHasher',
                ])
                django.setup()

            from django.contrib.auth.hashers import check_password
            is_valid_pass = check_password(password, password_hash)

            if not is_valid_pass:
                return {
                    "success": False,
                    "error": f"Invalid credentials. Password verification failed for '{email}'."
                }

            return {
                "success": True,
                "email": db_email,
                "role": role,
                "message": "Primary authentication verified against osivault_admin_account table!"
            }
        except Exception as e:
            return {"success": False, "error": f"Database Authentication Error: {str(e)}"}


def start_server(port=3000):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, CustomHTTPRequestHandler)
    httpd.serve_forever()


def main():
    print("=" * 65)
    print("  OSIVault Enterprise Desktop Admin Panel Launcher")
    print(f"  Resolved UI Directory: {UI_DIR}")
    print("=" * 65)
    
    port = 3000
    server_thread = threading.Thread(target=start_server, args=(port,), daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{port}/"
    print(f"Opening OSIVault Native Desktop GUI Application at {url}...")

    try:
        import webview
        webview.create_window(
            "OSIVault Desktop Admin Panel - Enterprise Security GUI",
            url=url,
            width=1400,
            height=900,
            resizable=True,
            min_size=(1024, 700)
        )
        webview.start()
    except Exception as e:
        print(f"Native webview fallback to browser: {e}")
        import webbrowser
        webbrowser.open(url)


if __name__ == "__main__":
    main()
