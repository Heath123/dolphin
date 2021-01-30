//
// Created by heath on 27/01/2021.
// TODO: put everything in the right place and clean it up and everything
//

#ifndef DOLPHIN_EMU_MOD_H
#define DOLPHIN_EMU_MOD_H


#include <string>
#include <vector>

enum ModType
{
    LayeredFS, Riivolution
};

/*
File::AddToFileTree(rootEntry, "/Race/Course/ridgehighway_course.szs",
    "/media/heath/Windows/Users/User/Desktop/ridgehighway_course_halogen.szs", false, false);
*/
class Patch
{
public:
    std::string discPath;
    std::string physicalPath;
    bool createIfNotExists;
    bool createFullPath;
};

// TODO: convert to abstract class, or interface if no code needed?
class Mod
{
public:
    std::string name;
    std::vector<Patch> patches;
    ModType type;
};

class RiivolutionMod: public Mod {
public:
    void readFromXML(std::string path, std::string virtualSDRoot);
};

#endif //DOLPHIN_EMU_MOD_H
