#include "MainWindow.h"
#include <QApplication>
#include <QStandardPaths>
#include <QDir>
#include "version.h"  

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/space.png"));
    QApplication::setApplicationName("ShodanViewer");
    QApplication::setOrganizationName("ShodanViewer");
    QApplication::setApplicationVersion(SHODAN_VIEWER_VERSION);

    const QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dataDir);

    MainWindow window;
    window.show();
    return app.exec();
}
