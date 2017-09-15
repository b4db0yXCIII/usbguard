//
// Copyright (C) 2017 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Authors: Daniel Kopecek <dkopecek@redhat.com>
//
#ifdef HAVE_BUILD_CONFIG_H
#include <build-config.h>
#endif

#include "LinuxAuditBackend.hpp"

#include <usbguard/Exception.hpp>
#include <Common/Utility.hpp>

#include <stdexcept>

#if defined(HAVE_LINUX_AUDIT)
#include <libaudit.h>
#endif

#ifndef AUDIT_USER_DEVICE
#define AUDIT_USER_DEVICE 1137 /* User space hotplug device changes */
#endif

namespace usbguard
{
  LinuxAuditBackend::LinuxAuditBackend()
  {
#if defined(HAVE_LINUX_AUDIT)
    if ((_audit_fd = audit_open()) < 0) {
      throw ErrnoException("LinuxAuditBackend", "audit_open", errno);
    }
#else
    (void)_audit_fd;
    throw std::runtime_error("LinuxAuditBackend: not supported");
#endif
  }

  LinuxAuditBackend::~LinuxAuditBackend()
  {
#if defined(HAVE_LINUX_AUDIT)
    audit_close(_audit_fd);
#endif
  }

  void LinuxAuditBackend::write(const AuditEvent& event)
  {
#if defined(HAVE_LINUX_AUDIT)
    std::string message;
    /*
     * Linux Audit event result
     *  0 = failed
     *  1 = success
     */
    int result = 0;

    message.append("uid=");
    message.append(numberToString(event.identity().uid()));
    message.append(" ");

    message.append("pid=");
    message.append(numberToString(event.identity().pid()));
    message.append(" ");

    for (const auto& kv_pair : event.keys()) {
      const std::string& key = kv_pair.first;
      const std::string& value = kv_pair.second;

      if (key == "result") {
        if (value == "SUCCESS") {
          result = 1;
        }
      }
      else {
        message.append(key);
        message.append("='");
        message.append(value);
        message.append("' ");
      }
    }
    audit_log_user_message(_audit_fd, AUDIT_USER_DEVICE, message.c_str(),
      /*hostname=*/nullptr, /*addr=*/nullptr, /*tty=*/nullptr, result);
#else
    (void)event;
    throw std::runtime_error("LinuxAuditBackend::write: not supported");
#endif
  }
}
/* vim: set ts=2 sw=2 et */