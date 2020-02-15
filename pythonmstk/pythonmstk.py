#!/usr/bin/python3
# pythonmstk
# python module that supports mstk daemmons

import sys,os
import re
import configparser
from . import mydb
import json
import time
import arpreq
from pythoncivicrm import CiviCRM
from pythoncivicrm import CivicrmError
import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()
from slacker import Slacker


class MstkServer:
   
   def __init__(self, secrets_path,secrets_file):

      config = configparser.ConfigParser()
      config.read(os.path.join(secrets_path, secrets_file))
      civicrm_url = config.get('civi-connect', 'url')
      civicrm_site_key = config.get('civi-connect', 'site_key')
      civicrm_api_key = config.get('civi-connect', 'api_key')
      civicrm_ssl = config.get('civi-connect', 'use_ssl')
      civicrm_ssl = False if civicrm_ssl == "False" else True
      self.slack = Slacker(config.get('slack', 'slackapi'))
      self.slack_enabled = config.get('slack','slack_enabled')
      self.slack_channel = config.get('slack','slack_channel')
      self.log_level = int(config.get('mstk', 'log_level'))

      hostname = config.get('dbconnect', 'host')
      dbport = int(config.get('dbconnect', 'port'))
      username = config.get('dbconnect', 'user')
      password = config.get('dbconnect', 'passwd')
      database  = config.get('dbconnect', 'db')
      
      db = mydb.disconnectSafeConnect(host=hostname,
      port=dbport,
      user=username, 
      passwd=password, 
      db=database) 

      self.cur = db.cursor()

      self.civicrm = CiviCRM(civicrm_url, civicrm_site_key, civicrm_api_key, use_ssl=civicrm_ssl, timeout=10 )
      
      daemon = secrets_file.rstrip("-secrets.conf")
      
      # this log is also used for slack and it's #doorbot channel
      self.accesslogfile = ('/var/log/%s.access.log' % daemon)
      open(self.accesslogfile,'a').close()
      # this log is for any bs we may encounter, unauthorized APs etc
      self.activity_logfile = ('/var/log/%s.activity.log' % daemon) 
      open(self.activity_logfile, 'a').close()
      
   def debug_message(self,current_log_level, message_level, message):
      timestamp = time.strftime('%Y%m%d_%H:%M:%S')
      if message_level <= current_log_level:
         print("%s - %s" % (timestamp, message))
         logfile = open(self.activity_logfile, "a");
         logfile.write("%s - %s" % (timestamp, message))
         logfile.write("\n")
         logfile.close()
   
   '''
   logsearch is for slack-posting the first usage per day of an access point to a 
   specific  lack channel. If  no slack_channel arg is passed, the default is used 
   from the config.
   '''
   
   def logsearch(self,entrydate, entryname, statuscode, slack_channel=None):
      if self.slack_enabled == 'True':
         if slack_channel == None:
            slack_channel = self.slack_channel
         today = time.strftime("%m/%d/%Y")
         currenttime  = time.strftime("%H:%M:%S")
         datevalue = None
         for dates in open(self.accesslogfile,encoding="latin-1"):
            namevalue = None
            if entrydate in dates:
               datevalue = 1
               for names in dates.splitlines():
                  if entryname in names:
                     namevalue = 1
                     print ('the name %s is found' % entryname )
                     return
         else:
            if not datevalue or not namevalue:
                loglist = [entrydate,currenttime,entryname,statuscode]
                logline = str(loglist).replace('[','').replace(']','').replace("'","")
                self.slack.chat.post_message(str(slack_channel), logline, as_user=False)
   
   '''
       Retreive user's memeber status. Returns bool
   '''
   
   def membership_check(self,contact_id):
       membership_status = 0
       search_dict = {
                     "contact_id":contact_id,
                     "sort":"status_id ASC",
                     }
       try:
          self.cur.execute("SELECT * FROM civicrm_membership WHERE contact_id = %s ORDER BY status_id ASC", (contact_id,))
          member = self.cur.fetchone()
          # map CiviCRM member states to boolean
          membership_status = 0 if int(member['status_id']) >= 3 else 1
       except:
          # no member record
          return 0
   
       return membership_status
   
   '''
       card_lookup returns a dictionary of user info
   '''
   def card_lookup (self,card_number, **access_point):
      # set some defaults
      member_status = 0
      contact_id = 0
      if not self.cur.execute("SELECT * FROM civicrm_accesscard_cards WHERE card_id = %s", (card_number,)):
         today = time.strftime("%m/%d/%Y")
         currenttime  = time.strftime("%H:%M:%S")
         logfile = open(self.accesslogfile, "a");
         logfile.write("%s,%s,unknowncard-%s,0\n" % (str(today), str(currenttime), str(card_number)))
         logfile.close()
         self.debug_message(self.log_level,0, "unknown card id %s at accesspoint %s" % (card_number, access_point['id']))
         display_name = "Unknown Card"
         access = 0
         error_code = "x80"
         user_dict = {
                     "display_name":str(display_name),
                     "contact_id":str(contact_id),
                     "access_point":str(access_point['id']),
                     "access":str(access),
                     "member_status":str(member_status),
                     "error_code":str(error_code)
                     }
         print ("unknown card id")
         return user_dict
      else:
         card_record = self.cur.fetchone()
         contact_id = card_record['contact_id']
         #print('contact id is %s' % contact_id)
         self.cur.execute("SELECT * FROM civicrm_contact WHERE id = %s", (contact_id,))
         contact = self.cur.fetchone()
         member_status = self.membership_check(contact_id)
         print('member status is %s' % member_status)
         display_name= contact['display_name']
         self.debug_message(self.log_level, 3, "member status for %s is %s" % (contact_id,member_status))
         access = self.acl_check("UserAcls",contact_id,**access_point).split(".")[0]
         error_code = "x00" if str(access) == "1" else "x01"
         user_dict = {
           "display_name":str(display_name),
           "contact_id":str(contact_id),
           "access_point":str(access_point['id']),
           "access":str(access),
           "member_status":str(member_status),
           "error_code":str(error_code)
         }
         return user_dict
   
   '''
      Fucnction to check if contact has requested permission. Accepts contact id and door Id. Returns bool.
   '''
   
   def acl_check(self,entity,iD,**access_point):
      # returns bool. this is where we check permissions
      # order is useracl for AP, useracl for parent APs,
      # groupacls for AP, groupacls for parent APs.
      aco_record = {}
   
      if entity == "UserAcls":
         search_param = 'contact_id'
         search_table = 'civicrm_mstk_user_acls'
      elif entity == "GroupAcls":
         search_param = "group_id"
         search_table = "civicrm_mstk_group_acls"
      print('in acl_check, ap is %s, iD is %s and entity is %s' % (access_point['id'],iD,entity))
      select_query ="""SELECT * FROM  %s WHERE aco = %s AND %s = %%s;""" % (search_table,access_point['id'], search_param)
      if self.cur.execute(select_query,(iD,)):
         aco_record = self.cur.fetchone()
         #print('aco record is %s' % aco_record)
         print('acl status is %s' % aco_record['status_id'])
         if int(aco_record['status_id']) > 1:
            print('revoked or expired')
            return "0.%s.%s.%s" % (entity,aco_record['status_id'],access_point['id']) 
         elif int(aco_record['status_id']) == 1:
            print('direct acl found and active')
            return "1.%s.%s.%s" % (entity,aco_record['status_id'],access_point['id']) 
   
      else:
         print("no direct %s" % entity )
         pass
   
      # no match yet, let's see if the ap has a parent where an acl exists.
   
      ap_parent_id = access_point['parent_id']
      print('ap_parent_id is %s' % ap_parent_id)
      if ap_parent_id:
         print("ap parent id is %s"  % ap_parent_id)
         self.cur.execute("SELECT * FROM civicrm_mstk_access_points WHERE id = %s", (ap_parent_id,))
         parent_access_point = self.cur.fetchone()
        # infinite recursion \o/
         access = self.acl_check(entity,iD,**parent_access_point)
         if access and access.split(".")[0] == "1":
           return access 
      else:
         print("no parent aps for aco %s"  % access_point)
         # end recursion
         return 
   
      print('access point should not be parent, it is %s' % access_point)
   
      # no match yet, let's move on to groupacls. First find what groups user belongs to.
      # there's no way to directly find smart group membership. so we're getting all groups
      # with Contact api
   
      if entity == "UserAcls":
         search_dict = {
             "id":str(iD),
              "return":"group",
         }
         try:
            search_results = self.civicrm.get("Contact", **search_dict)
            print(json.dumps(search_results))
            groups_string = search_results[0]['groups']
            groups = groups_string.split(",")
            # ouch, to give precedence to child groups we have to figure our relationships first.
            # get the whole list of gids, order the list and process.
            for group_title in groups:
               print('group title is %s' % group_title)
               self.cur.execute("SELECT * FROM civicrm_group  WHERE title = %s", (group_title,))
               gid_search = self.cur.fetchone()
               gid = gid_search['id']
               print('gid is %s' % gid)
               access = self.acl_check("GroupAcls",gid,**access_point)
               if access and access.split(".")[0] == "1":
                  print('group acl is good')
                  return access 
               else:
   
                  # check for parent group
                  if self.cur.execute("SELECT * FROM civicrm_group_nesting  WHERE child_group_id = %s", (gid,)):
                     parent_search = self.cur.fetchone()
                     print('parent civi group id is %s' % parent_search['parent_group_id'])
                     # more recursion
                     access = self.acl_check("GroupAcls",parent_search['parent_group_id'],**access_point)
                     if access and access.split(".")[0] == "1":
                        print('civi parent group %s match with ap %s' % (parent_search['parent_group_id'],access_point['id']))
                        return access
                  else:
                     print('no parent groups found')
                     pass
         except:
            print('no direct groups')
            return "0.%s.0.%s" % (entity,access_point['id']) 
         print('entity is %s' % entity) 
         return "0.%s.0.%s" % (entity,access_point['id']) 
   
   '''
   ap_lookup returns a dictionary of ap info appending an error code.
   this authenticates the user as well as the machine against the mstk
   access points in our db.
   
   '''
   def ap_lookup(self,client_ip):
      requesting_mac = arpreq.arpreq(client_ip) 
      if not self.cur.execute("SELECT *, CAST(non_member_perdiem AS CHAR) AS non_member_perdiem,CAST(non_member_rate AS CHAR) AS non_member_rate,CAST(member_rate AS CHAR) AS member_rate FROM civicrm_mstk_access_points WHERE mac_address = %s", (requesting_mac,)):
         self.debug_message(self.log_level, 0, "UNAUTHORIZED AP REQUEST: by ip address %s with mac address %s" % (client_ip, requesting_mac))
         return {'error_code' :'x10'}
      else:
         requesting_ap = self.cur.fetchone()
   
      if requesting_ap['ip_address'] == client_ip:
         # Ok, this is a legit ap.
         if str(requesting_ap['maintenance_mode']) == "1":
            error_code = 'x20' 
            requesting_ap.update({
              "error_code":str(error_code)
            })
         else:
            # adding door comands if this is under an access control device
            try:
               requesting_ap.update({
                  "dev":str(requesting_ap['dev'])
               })
               requesting_ap.update({
                  "cmd":str(requesting_ap['cmd'])
               })
            except:
               pass
            # adding a parent if present
            try:
               requesting_ap.update({
                  "parent_ap":str(requesting_ap['parent_id'])
               })
            except:
               # no parent
               pass
   
            error_code = 'x00'
            requesting_ap.update({
              "error_code":str(error_code)
            })
   
         return requesting_ap
      else:
         self.debug_message(self.log_level, 0, "UNAUTHORIZED AP REQUEST: ip/mac don't agree. ip %s, mac %s" % (client_ip, requesting_mac))
         return {'error_code' :'x10'}
 

