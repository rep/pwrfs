
import sys
import os
import struct
import socket
import fcntl
import traceback
import errno
import stat

import pyev

from fusell import FUSELL
from pwrcall import loop, unloop, Node, expose, Promise
from evnet import later, listenplain, default_loop, EVException

HOST, PORT = '127.0.0.1', 0x10f5
REF = 'abcdefg'

class pwrfscli(object):
	def __init__(self, mountdir):
		self.mountdir = mountdir
		self.n = Node(cert=None)
		self.fuse = None
		later(0.0, self.connect)

	def connect(self):
		self.rc = self.n.connect(HOST, PORT)
		self.rc._on('ready', self.server_ready)
		self.rc._on('close', self.server_closed)

	def server_ready(self):
		print 'server ready.'
		if not self.fuse: self.fuse = pwrfuse(self.mountdir, self)

	def server_closed(self, e):
		print 'server closed.', e
		later(5.0, self.connect)

	def call(self, *args, **kwargs):
		try: return self.rc.call(REF, *args, **kwargs)
		except EVException:
			p = Promise()
			p._smash(EVException('Server currently unavailable.'))
			return p

	def _unmount(self):
		if self.fuse: self.fuse._unmount()

class pwrfuse(FUSELL):
	def __init__(self, mountdir, cli):
		FUSELL.__init__(self, mountdir)
		print 'bufsize chan', self.libfuse.fuse_chan_bufsize(self.chan)
		self.mountdir = mountdir
		self.c = cli

		self._closed = False
		fd = self._chanfd()
		fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
		self.read_watcher = pyev.Io(fd, pyev.EV_READ, default_loop, self._readable)
		self.read_watcher.start()

	def _readable(self, watcher, events):
		try:
			data = os.read(self._chanfd(), 131072)
		except OSError as e:
			if e.errno == errno.EAGAIN: return
			else: self._close(EVException('Exception {0}'.format(e)))
		except Exception as e:
			self._close(EVException('Exception {0}'.format(e)))
		else:
			if not data:
				self._close(EVException('Connection closed. not data'))
			elif len(data) == 0:
				self._close(EVException('Connection closed. len data = 0'))
			else:
				try:
					self.libfuse.fuse_session_process(self.session, data, len(data), self.chan)
				except:
					traceback.print_exc()


	def _close(self, e):
		print '_close', e
		self._closed = True
		self.read_watcher.stop()
		print 'unmounting...'
		self._unmount()
		print 'unlooping...'
		unloop()

	def tctx(self, req):
        	ctx = self.req_ctx(req)
		return {'uid': ctx['uid'], 'gid': ctx['gid'], }

	def do_reply_attr(self, attr, req):
		print 'do_reply_attr', attr, req
		self.reply_attr(req, attr, 1.0)

	def do_reply_entry(self, entry, req):
		print 'do_reply_entry', entry, req
		self.reply_entry(req, entry)

	def do_reply_create(self, result, req, fi):
		entry, fh = result
		print 'do_reply_create', entry, fh, req	
		fi['fh'] = fh
		self.reply_create(req, entry, fi)

	def do_reply_buf(self, buf, req):
		self.reply_buf(req, buf)

	def do_reply_write(self, lenbuf, req):
		self.reply_write(req, lenbuf)

	def do_reply_readdir(self, entries, req, size, off):
		print 'do_reply_readdir', entries, req
		self.reply_readdir(req, size, off, entries)

	def do_reply_open(self, handle, req, fi):
		fi['fh'] = handle
		self.reply_open(req, fi)

	def do_reply_none(self, e, req):
		self.reply_none(req)

	def do_reply_err(self, e, req):
		print 'do_reply_err', e, req
		try: e = int(e)
		except: e = errno.EFAULT
		self.reply_err(req, e)

	def getattr(self, req, ino, fi):
		print 'getattr:', ino, fi
		p = self.c.call('getattr', ino, fi)
		p._when(self.do_reply_attr, req)
		p._except(self.do_reply_err, req)

	def lookup(self, req, parent, name):
		print 'lookup:', parent, name
		p = self.c.call('lookup', parent, name)
		p._when(self.do_reply_entry, req)
		p._except(self.do_reply_err, req)

	def mkdir(self, req, parent, name, mode):
		print 'mkdir:', parent, name, mode
		ctx = self.tctx(req)
		p = self.c.call('mkdir', ctx, parent, name, mode)
		p._when(self.do_reply_entry, req)
		p._except(self.do_reply_err, req)

	def open(self, req, ino, fi):
		print 'open:', ino, fi
		p = self.c.call('open', ino, fi)
		p._when(self.do_reply_open, req, fi)
		p._except(self.do_reply_err, req)

	def readdir(self, req, ino, size, off, fi):
		print 'readdir:', ino, size, off, fi
		p = self.c.call('readdir', ino, size, off, fi)
		p._when(self.do_reply_readdir, req, size, off)
		p._except(self.do_reply_err, req)
		
	def read(self, req, ino, size, off, fi):
		p = self.c.call('read', ino, size, off, fi)
		p._when(self.do_reply_buf, req)
		p._except(self.do_reply_err, req)

	def write(self, req, ino, buf, off, fi):
		p = self.c.call('write', ino, buf, off, fi)
		p._when(self.do_reply_write, req)
		p._except(self.do_reply_err, req)

	def create(self, req, parent, name, mode, fi):
		print 'create:', parent, name, mode, fi
		ctx = self.tctx(req)
		p = self.c.call('create', ctx, parent, name, mode, fi)
		p._when(self.do_reply_create, req, fi)
		p._except(self.do_reply_err, req)
	
	def forget(self, req, ino, nlookup):
		print 'forget:', ino, nlookup
		p = self.c.call('forget', ino, nlookup)
		p._when(self.do_reply_none, req)
		p._except(self.do_reply_none, req)

	def setattr(self, req, ino, attr, to_set, fi):
		print 'setattr:', ino, attr, to_set
		p = self.c.call('setattr', ino, attr, to_set, fi)
		p._when(self.do_reply_attr, req)
		p._except(self.do_reply_err, req)
		
	def readlink(self, req, ino):
		print 'readlink:', ino
		self.reply_err(req, errno.ENOENT)
	
	def mknod(self, req, parent, name, mode, rdev):
		print 'mknod:', parent, name, mode
		self.reply_err(req, errno.EROFS)

	def unlink(self, req, parent, name):
		print 'unlink:', parent, name
		p = self.c.call('unlink', parent, name)
		p._when(self.do_reply_err, req)
		p._except(self.do_reply_err, req)
	
	def rmdir(self, req, parent, name):
		print 'rmdir:', parent, name
		self.reply_err(req, errno.EROFS)
	
	def symlink(self, req, link, parent, name):
		print 'symlink:', link, parent, name
		self.reply_err(req, errno.EROFS)
	
	def rename(self, req, parent, name, newparent, newname):
		print 'rename:', parent, name, newparent, newname
		p = self.c.call('rename', parent, name, newparent, newname)
		p._when(self.do_reply_err, req)
		p._except(self.do_reply_err, req)
	
	def link(self, req, ino, newparent, newname):
		print 'link(hard):', ino, newparent, newname
		self.reply_err(req, errno.EROFS)
	
	def flush(self, req, ino, fi):
		print 'flush:', ino
		self.reply_err(req, 0)
	
	def release(self, req, ino, fi):
		print 'release:', ino
		p = self.c.call('release', ino, fi)
		p._when(self.do_reply_err, req)
		p._except(self.do_reply_err, req)
	
	def fsync(self, req, ino, datasync, fi):
		print 'fsync:', ino, datasync
		self.reply_err(req, 0)

	def opendir(self, req, ino, fi):
		print 'opendir:', ino
		self.reply_open(req, fi)
	
	def releasedir(self, req, ino, fi):
		print 'releasedir:', ino
		self.reply_err(req, 0)

	def fsyncdir(self, req, ino, datasync, fi):
		print 'fsyncdir:', ino, datasync
		self.reply_err(req, 0)


def main():
	mountdir = sys.argv[1]
	#secret = sys.argv[2]

	c = pwrfscli(mountdir)
	loop()
	c._unmount()
	return 0
	
if __name__ == '__main__':
	sys.exit(main())

