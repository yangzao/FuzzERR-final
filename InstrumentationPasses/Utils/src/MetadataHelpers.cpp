//
// Created by machiry on 4/19/22.
//

#include "MetadataHelpers.h"

std::string getFileName(Function &F) {
    DISubprogram *SP = F.getSubprogram();
    auto sref = SP->getDirectory();
    std::string FileName = sref.str() + '/' + SP->getFilename().str();
    // dbgs() << "FileName: " << FileName << '\n';
    return FileName;
}
