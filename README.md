# dokuwiki-plugin-authdrupal8
Authentication plugin for dokuwiki, authenticate with drupal8 drupal9 accounts

This plugin might be useful if you are running a drupal8 website and want to give your drupal users access to a dokuwiki using the same login credentials.

If you install this plugin manually, make sure it is installed in
lib/plugins/authdrupal8/ - if the folder is called different it
will not work!

Please refer to http://www.dokuwiki.org/plugins for additional info
on how to install plugins in DokuWiki.

----

This plugin is widely based on

Dokuwiki MySQL authentication backend by
* Matthias Jung <matzekuh@web.de>

and
* Andreas Gohr <andi@splitbrain.org>
* Chris Smith <chris@jalakai.co.uk>
* Matthias Grimm <matthias.grimmm@sourceforge.net>
* Jan Schumann <js@schumann-it.com>

and
DokuDrupal Drupal 7.x/MySQL authentication backend by
* Alex Shepherd <n00bATNOSPAMn00bsys0p.co.uk>

mysqli fix by
* Miro Janosik <miro.janosik.geo+ad7@gmail.com>

----
## Configuration
The plugin will only work if you have a drupal installation accessible.

In configuration backend you have to edit at least the following entries:
* MySQL server
* MySQL user and password
* MySQL database holding your drupal tables
* The database prefix used for your drupal tables (including the underscore e.g. ```myprefix_```)

**Before** setting your authentication mode to ```authdrupal8``` you should think about the following:
Dokuwiki might only grant access to users that are member of a defined user group. This plugin is reading the user groups from your database.
Make sure, that you use the exact same user group names in the ACL controls. Otherwise you might not be able to get access to your wiki or your adminstration panel although you are able to log in using correct credentials.

Easiest way is to go to Admin panel/Config/authentication section Security settings and here select :
* authtype authdrupal8
* passcrypt sha512
* administrator: add a administrator group (with @) or username that matches one of your drupal8 administrator roles
* manager: add a manager group (with @) or username that matches one of your drupal roles or users

----

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License
