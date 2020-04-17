"""
<filename>.py

Author: Desmond Tan
"""

#################
# Imports
#################

from flask import Flask, render_template, redirect, url_for, request, Response, flash, session, g
from flask_restful import Api, Resource, reqparse

import sqlite3
import requests
import json
from threading import Thread
from queue import Queue
import time
import os

import yara
