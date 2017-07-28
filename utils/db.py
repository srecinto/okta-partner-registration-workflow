import sqlite3

class PartnerDB:
    
    DB_FILE = None
    
    def __init__(self, db_file_path_and_name):
        print "PartnerDB.__init__"
        print "db_file_path_and_name: {0}".format(db_file_path_and_name)
        self.DB_FILE = db_file_path_and_name
    
    def test(self):
        print "test()"
        print "Connecting to DB: {0}".format(self.DB_FILE)
        conn = sqlite3.connect(self.DB_FILE)
        
        cur = conn.cursor()
        
        cur.execute("insert into partner_approval_queue values('123456', '11111');")
        
        cur.execute("select * from partner_approval_queue;")
        
        print "SQL Results: {0}".format(cur.fetchone())
        
        cur.execute("delete from partner_approval_queue;")
        
        print "SQL Results: {0}".format(cur.fetchone())
        
        conn.commit()
        conn.close()
        