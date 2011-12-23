#!/usr/bin/python
# -*- coding: utf8 -*-

import os
import sys
import errno
import time
import stat
import struct
import logging
logging.basicConfig(level=logging.DEBUG)

from pwrcall import loop, unloop, Node, expose, Promise
from pwrcall.util import NodeException
from evnet import later, listenplain

PORT = 0x10f5
SDIR = './share/'

statproperties = ('st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid')

def p(*args):
	path = os.path.normpath(os.path.join(SDIR, *args))
	if '..' in path: raise NodeException(errno.EPERM)
	return path

def stat2dict(st):
	return dict((key, getattr(st, key)) for key in statproperties)

def stat2dict2(st):
	return dict((key, getattr(st, key)) for key in ('st_mode', 'st_ino',))

def rand64():
	return struct.unpack('Q', os.urandom(8))[0]

class FSException(Exception):
	pass

class Fileserver(object):
	def __init__(self):
		self.ino = 1
		self.pathcache = {1:p('')}
		self.filehandles = {}
		later(20.0, self.outputstats)

	def outputstats(self):
		print 'STATS'
		print '  -> PATHCACHE', self.pathcache
		print '  -> FILEHANDLES', self.filehandles
		later(20.0, self.outputstats)

	@expose
	def getattr(self, ino, fi):
		print 'getattr:', ino
		path = self.pathcache.get(ino, None)
		if path == None: raise NodeException(errno.ENOENT)
		else: return stat2dict(os.lstat(path))

	@expose	
	def lookup(self, parent, name):
		print 'lookup:', parent, name
		fp = self.get_fullpath(parent, name)
 		if not os.path.exists(fp): raise NodeException(errno.ENOENT)
		return self.get_entry(fp)

	@expose
	def open(self, ino, fi):
		fp = self.get_fullpath(ino)
		print 'open:', ino, fi, fp
 		#if not os.path.exists(fp): raise NodeException(errno.ENOENT)
		fh = rand64()
		#self.filehandles[fh] = open(fp, 'rwb')
		self.filehandles[fh] = os.open(fp, os.O_RDWR)
		return fh

	def get_fullpath(self, ino, name=None):
		path = self.pathcache.get(ino, None)
		if path == None: raise NodeException(errno.ENOENT)
		cp = os.path.join(path)
		if name != None: cp = os.path.join(cp, name)
		return cp

	def get_entry(self, path):
		stat = os.lstat(path)
		self.pathcache[stat.st_ino] = path
		
		entry = {'ino': stat.st_ino, 'attr': stat2dict(stat), 'attr_timeout': 5.0, 'entry_timeout': 5.0}
		return entry

	@expose	
	def mkdir(self, ctx, parent, name, mode):
		print 'mkdir:', parent, name
		cp = self.get_fullpath(parent, name)
 		if os.path.exists(cp): raise NodeException(errno.EEXIST)
		
		os.mkdir(cp, mode)
		return self.get_entry(cp)
	
	@expose
	def read(self, ino, size, off, fi):
		print 'read', size, off, fi
		buf = os.read(self.filehandles[fi['fh']], size)
		return buf

	@expose	
	def readdir(self, ino, size, off, fi):
		fp = self.get_fullpath(ino)
		print 'readdir', ino, fp
 		if not os.path.exists(fp) or not os.path.isdir(fp): raise NodeException(errno.ENOENT)

		ppath, dirname = os.path.split(fp.rstrip('/'))
		print 'readdir:', ino, 'fp', fp, 'ppath', ppath, 'dirname', dirname
		if ppath == '': ppath = os.path.join(fp, '../')

		pstat = os.lstat(ppath)
		stat = os.lstat(fp)
		self.pathcache[stat.st_ino] = fp
		self.pathcache[pstat.st_ino] = ppath

		entries = [('.', stat2dict2(stat)),
			('..', stat2dict2(pstat))]

		for elem in os.listdir(fp):
			stat = os.lstat(os.path.join(fp,elem))
			self.pathcache[stat.st_ino] = os.path.join(fp,elem)
			entries.append((elem, stat2dict2(stat)))

		return entries
	
	@expose
	def rename(self, parent, name, newparent, newname):
		print 'rename:', parent, name, newparent, newname
		fp1 = self.get_fullpath(parent, name)
 		if not os.path.exists(fp1): raise NodeException(errno.ENOENT)
		fp2 = self.get_fullpath(newparent, newname)

		os.rename(fp1, fp2)
		return 0

	@expose
	def unlink(self, parent, name):
		print 'unlink:', parent, name
		fp1 = self.get_fullpath(parent, name)
 		if not os.path.exists(fp1): raise NodeException(errno.ENOENT)

		os.unlink(fp1)
		return 0
	
	@expose
	def setattr(self, ino, attr, to_set, fi):
		print 'setattr:', ino, attr, to_set
		fp = self.get_fullpath(ino)
		print ' -> file:', fp
 		if not os.path.exists(fp): raise NodeException(errno.ENOENT)

		e = self.get_entry(fp)

		for key in to_set:
			if key == 'st_mode':
				newmode = stat.S_IFMT(attr['st_mode']) | stat.S_IMODE(e['attr']['st_mode'])
				os.chmod(fp, newmode)
				e['attr']['st_mode'] = newmode
			elif key == 'st_size':
				fd = os.open(fp, os.O_RDWR | os.O_CREAT)
				os.ftruncate(fd, attr['st_size'])
				os.close(fd)
				e['attr']['st_size'] = attr['st_size']
		return e['attr']

	@expose	
	def write(self, ino, buf, off, fi):
		print 'write:', ino, off, fi
		os.write(self.filehandles[fi['fh']], buf)
		return len(buf)

	@expose	
	def create(self, ctx, parent, name, mode, fi):
		print 'create:', parent, name
		fp = self.get_fullpath(parent)
 		if not os.path.exists(fp) or not os.path.isdir(fp): raise NodeException(errno.ENOENT)
		filepath = os.path.join(fp, name)
		fd = os.open(filepath, os.O_CREAT | os.O_RDWR, mode)

		e = self.get_entry(filepath)
		fh = rand64()
		self.filehandles[fh] = fd
		return (e, fh)

	@expose
	def forget(self, ino, nlookup):
		#print 'forget:', ino, nlookup
		#fp = self.pathcache.pop(ino, None)
		#self.reply_none(req)
		return None

	@expose
	def release(self, ino, fi):
		print 'release:', ino, fi
		fd = self.filehandles.pop(fi['fh'], None)
		if fd != None: os.close(fd)
		#self.reply_err(req, 0)
		return 0


def main():
	global SDIR
	SDIR = sys.argv[1]
	secret = sys.argv[2]

	if not (os.path.exists(SDIR) and os.path.isdir(SDIR)):
		os.mkdir(SDIR)

	n = Node(cert=None)
	n.listen(port=PORT)
	gs = Fileserver()
	ref = n.register(gs, cap=secret)
	logging.info('gs at {0}'.format(n.refurl(ref)))

	loop()
	return 0

if __name__ == '__main__':
	sys.exit(main())

