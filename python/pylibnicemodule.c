
#include <config.h>
#define NO_IMPORT_PYGOBJECT
#include <pygobject.h>
 
void libnice_register_classes (PyObject *d); 
extern PyMethodDef libnice_functions[];
 
DL_EXPORT(void)
initlibnice(void)
{
    PyObject *m, *d;
 
    init_pygobject ();
 
    m = Py_InitModule ("libnice", libnice_functions);
    d = PyModule_GetDict (m);
 
    libnice_register_classes (d);
 
    if (PyErr_Occurred ()) {
        Py_FatalError ("can't initialise module libnice");
    }
}
