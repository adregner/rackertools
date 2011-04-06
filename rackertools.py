#!/usr/bin/python
# -*- coding: utf-8 -*-

########################################################################
# Copyright (C) 2011 by Alex Brandt <alunduil@alunduil.com>            #
#                                                                      #
# This program is free software; you can redistribute it and#or modify #
# it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or    #
# (at your option) any later version.                                  #
#                                                                      #
# This program is distributed in the hope that it will be useful,      #
# but WITHOUT ANY WARRANTY; without even the implied warranty of       #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        #
# GNU General Public License for more details.                         #
#                                                                      #
# You should have received a copy of the GNU General Public License    #
# along with this program; if not, write to the                        #
# Free Software Foundation, Inc.,                                      #
# 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.            #
########################################################################

from sys import argv, exit

from rackertools import RackerTools, RackerToolsException

try:
    import pycolorize
except:
    sys.path.append(os.path.dirname(__file__) + "/vendor/pycolorize")
    import pycolorize

if __name__ == "__main__":
    try:
        application = RackerTools(argv)
        application.Run()
    except RackerToolsException, e:
        if (len(e.GetMessage()) > 0): pycolorize.error(e.GetMessage())
        exit(1)
    exit(0)
