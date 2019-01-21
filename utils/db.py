import sqlite3


class PartnerDB:

    DB_FILE = None

    def __init__(self, db_file_path_and_name):
        print "PartnerDB.__init__"
        print "db_file_path_and_name: {0}".format(db_file_path_and_name)
        self.DB_FILE = db_file_path_and_name

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def get_connection(self):
        print "get_connection()"
        conn = sqlite3.connect(self.DB_FILE)
        conn.row_factory = self.dict_factory

        return conn

    def commit_close_connection(self, conn):
        print "commit_close_connection()"
        conn.commit()
        conn.close()

    def get_user_partner_role_by_group(self, group_id):
        print "get_user_partner_role_by_group()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (group_id,)
        cur.execute("select * from user_partner_role where okta_group_id=?;", params)

        result = cur.fetchall()

        self.commit_close_connection(conn)

        return result

    def delete_user_partner_role(self, user_id, group_id, role):
        print "delete_user_partner_role()"
        result = "SUCCESS"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            user_id,
            group_id,
            role
        )
        cur.execute("delete from user_partner_role where okta_user_id=? and okta_group_id=? and partner_role=?;", params)
        self.commit_close_connection(conn)

        return result

    def create_user_partner_role(self, user_id, group_id, role):
        print "create_user_partner_role()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            user_id,
            group_id,
            role
        )
        cur.execute("insert into user_partner_role values(?, ?, ?);", params)
        cur.execute("select * from user_partner_role;")

        result = cur.fetchone()

        self.commit_close_connection(conn)

        return result

    def create_partner_approval_queue(self, user_id, group_id):
        print "create_partner_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            user_id
        )
        cur.execute("insert into partner_approval_queue (okta_group_id, okta_user_id) values (?, ?);", params)
        cur.execute("select * from partner_approval_queue;")

        result = cur.fetchone()

        self.commit_close_connection(conn)

        return result

    def delete_partner_approval_queue(self, user_id, group_id):
        print "create_partner_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            user_id
        )
        cur.execute("delete from partner_approval_queue where okta_group_id=? and okta_user_id=?;", params)

        self.commit_close_connection(conn)


    def get_partner_admin_approval_queue(self):
        print "get_partner_admin_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("select * from admin_approval_queue;")

        result = cur.fetchall()

        self.commit_close_connection(conn)

        return result

    def create_application_approval_queue(self, user_id, group_id, app_id):
        print "create_application_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            user_id,
            app_id
        )
        cur.execute("insert into application_approval_queue (okta_group_id, okta_user_id, okta_app_id) values (?, ?, ?);", params)
        cur.execute("select * from partner_approval_queue;")

        result = cur.fetchone()

        self.commit_close_connection(conn)

        return result

    def delete_application_approval_queue(self, user_id, group_id, app_id):
        print "delete_application_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            user_id,
            app_id
        )
        cur.execute("delete from application_approval_queue where okta_group_id=? and okta_user_id=? and okta_app_id=?;", params)

        self.commit_close_connection(conn)


    def get_application_approval_queue_by_group(self, group_id):
        print "get_application_admin_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            )
        cur.execute("select * from application_approval_queue where okta_group_id=?;", params)

        result = cur.fetchall()

        self.commit_close_connection(conn)

        return result

    def create_partner_admin_approval_queue(self, user_id, group_id):
        print "create_partner_admin_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            user_id
        )
        cur.execute("insert into admin_approval_queue (okta_group_id, okta_user_id) values (?, ?);", params)
        cur.execute("select * from admin_approval_queue;")

        result = cur.fetchone()

        self.commit_close_connection(conn)

        return result

    def delete_partner_admin_approval_queue(self, user_id, group_id):
        print "delete_partner_admin_approval_queue()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_id,
            user_id
        )
        cur.execute("delete from admin_approval_queue where okta_group_id=? and okta_user_id=?;", params)

        self.commit_close_connection(conn)

    def get_field_partner_profile(self, field_name, constraint):
        print "get_field_partner_profile()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            '%'+constraint+'%',
        )
        cur.execute("select * from partner_profile where {field_name} like ?;".format(
            field_name=field_name), params)

        result = cur.fetchall()

        self.commit_close_connection(conn)

        return result

    def get_partner_profile_by_group(self, group_name):
        print "get_partner_profile_by_group()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_name,
        )
        cur.execute("select * from partner_profile where okta_group_name = ?;", params)

        result = cur.fetchone()

        self.commit_close_connection(conn)

        return result

    def create_partner_profile(self, group_name, zip_code):
        print "create_partner_profile()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (
            group_name,
            zip_code
        )
        cur.execute("insert into partner_profile (okta_group_name, group_zipcode) values (?, ?);", params)
        cur.execute("select * from partner_profile;")

        result = cur.fetchone()

        self.commit_close_connection(conn)

        return result

    def get_partner_approval_queue_by_group(self, group_id):
        print "get_partner_approval_queue_by_group()"
        conn = self.get_connection()
        cur = conn.cursor()
        params = (group_id,)
        cur.execute("select * from partner_approval_queue where okta_group_id=?;", params)

        result = cur.fetchall()

        self.commit_close_connection(conn)

        return result

    def get_roles(self):
        print "get_roles()"

        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("select * from role;")

        results = cur.fetchall()

        self.commit_close_connection(conn)

        return results

    def test(self):
        print "test()"
        print "Connecting to DB: {0}".format(self.DB_FILE)
        conn = self.get_connection()

        cur = conn.cursor()
        cur.execute("insert into partner_approval_queue values('123456', '11111');")
        cur.execute("select * from partner_approval_queue;")
        print "SQL Results: {0}".format(cur.fetchone())
        cur.execute("delete from partner_approval_queue;")
        print "SQL Results: {0}".format(cur.fetchone())

        self.commit_close_connection(conn)
