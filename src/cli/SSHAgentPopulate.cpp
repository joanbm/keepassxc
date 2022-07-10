/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "SSHAgentPopulate.h"

#include "Utils.h"
#include "core/Group.h"
#include "sshagent/KeeAgentSettings.h"
#include "sshagent/SSHAgent.h"

#include <QCommandLineParser>
#include <signal.h>

SSHAgentPopulate::SSHAgentPopulate()
{
    name = QString("ssh-agent-populate");
    description = QObject::tr("Adds keys to the SSH Agent, and removes them when a quit signal is received.");
    optionalArguments.append({QString("entry"),
        QObject::tr("Path of the entry. If not specified, defaults to adding all keys specified to load on database open."),
        QString("[entry]")});
    // TODO: Figure out if/how we can make multiple instances of KeePassXC (e.g. CLI and GUI) peacefully coexist,
    // without each instance removing the other's keys on close
}

static bool waitForQuitSignal() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, NULL);

    int sig;
    bool ret = sigwait(&set, &sig) != -1;
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    return ret;
}

int SSHAgentPopulate::executeWithDatabase(QSharedPointer<Database> database, QSharedPointer<QCommandLineParser> parser)
{
    auto& out = parser->isSet(Command::QuietOption) ? Utils::DEVNULL : Utils::STDOUT;
    auto& err = Utils::STDERR;

    const QStringList args = parser->positionalArguments();

    if (!sshAgent()->isEnabled()) {
        err << QObject::tr("The SSH agent is not enabled.") << endl;
        return EXIT_FAILURE;
    }

    if (args.size() == 1) {
        QObject::connect(sshAgent(), &SSHAgent::error, [&](const QString& message) {
            err << QObject::tr("Could not add OpenSSH key to the agent: %1").arg(message) << endl;
        });

        sshAgent()->databaseUnlocked(database);
    } else {
        const QString& entryPath = args.at(1);
        Entry* entry = database->rootGroup()->findEntryByPath(entryPath);
        if (!entry) {
            err << QObject::tr("Could not find entry with path %1.").arg(entryPath) << endl;
            return EXIT_FAILURE;
        }

        KeeAgentSettings settings;
        OpenSSHKey key;
        if (!settings.fromEntry(entry) || !settings.toOpenSSHKey(entry, key, true)) {
            err << QObject::tr("Could not retrieve the OpenSSH key associated to the entry.") << endl;
            return EXIT_FAILURE;
        }

        if (!sshAgent()->addIdentity(key, settings, database->uuid())) {
            err << QObject::tr("Could not add OpenSSH key to the agent: %1").arg(sshAgent()->errorString()) << endl;
            return EXIT_FAILURE;
        }
    }
    out << QObject::tr("Key(s) added to SSH agent, waiting for exit signal...") << endl;

    int ret = EXIT_SUCCESS;
    if (!waitForQuitSignal()) {
        err << QObject::tr("Failed to wait for signal") << endl;
        ret = EXIT_FAILURE;
    }

    sshAgent()->databaseLocked(database);
    out << QObject::tr("Key(s) removed from SSH agent") << endl;

    return ret;
}
