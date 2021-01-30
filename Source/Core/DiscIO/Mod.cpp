//
// Created by heath on 27/01/2021.
// TODO: put everything in the right place and clean it up and everything
//

#include "Mod.h"

#include <iostream>
#include <vector>
#include <algorithm>
#include <pugixml.hpp>

// using namespace std;

void RiivolutionMod::readFromXML(std::string path, std::string virtualSDRoot)
{
  name = "mod"; // TODO

  std::vector<std::string> enabledPatches = {"CTsFTW", "cvfix"};

  // TODO: Handle load errors
  pugi::xml_document doc;
  pugi::xml_parse_result result = doc.load_file(path.c_str());

  std::cout << "Load result: " << result.description() << std::endl;
  std::cout << "Mesh name: " << doc.child("wiidisc").child("patch").path() << std::endl;

  auto root = doc.child("wiidisc");

  for (pugi::xml_node patch: root.children("patch"))
  {
    std::string patchName = patch.attribute("id").value();
    if (count(enabledPatches.begin(), enabledPatches.end(), patchName))
    {
      std::cout << "Found enabled patch: " << patchName << std::endl;

      for (pugi::xml_node individual_patch: patch.children())
      {
        std::string patch_type = individual_patch.name();
        if (patch_type == "file") {
          // https://rvlution.net/wiki/Patch_Format/#File_Patch
          // TODO: Error when required fields are missing

          // disc - disc path - required - The file on disc to replace. This can be rooted as a full disc path or just a filename to search for.
          // TODO: implement searching
          std::string disc = individual_patch.attribute("disc").as_string("/");
          std::cout << "Disc path: " << disc << std::endl;

          // external - path - required - The file on SD/USB to replace the disc file with.
          std::string external = individual_patch.attribute("external").as_string("/");
          std::cout << "External path: " << external << std::endl;

          // TODO: Implement resize (what happens if it's set to false and the size is different? Does it get truncated/padded?)
          // resize - boolean - optional - Defaults to true, specifies whether to resize the disc file to the external file.

          // create - boolean - optional - Defaults to false, specifies whether to add the file on the disc if it does not exist.
          bool create = individual_patch.attribute("create").as_bool(false);
          std::cout << "Create: " << create << std::endl;

          // TODO: Implement offset
          // offset - integer - optional - The offset into the disc file to start replacing; defaults to 0 (beginning of the file).

          // TODO: Implement length
          // length - integer - optional - The length specifies how much to patch the file. If not specified, or set to 0, it will default to the size of the external file.

          Patch patch;
          patch.createFullPath = false; // Currently broken in the AddToFileTree function :(
          patch.createIfNotExists = create;
          patch.discPath = disc;
          patch.physicalPath = virtualSDRoot + external; // TODO: use some sort of path.json thing

          patches.push_back(patch);
        } else {
          std::cout << "Unimplemented patch type: " << patch_type << std::endl;
        }
      }
    } else {
      std::cout << "Found disabled patch: " << patchName << std::endl;
    }
  }
}