import { SectionType } from "../../entities/Section";
import { ResourceType } from "../../entities/SectionResourceMap";

// This map defines exactly which resources are allowed in which section types.
// When you add a new SectionType in the future, you ONLY update this object!
export const AllowedResourcesBySectionType: Record<SectionType, ResourceType[]> = {
    [SectionType.MCQ]: [ResourceType.MCQ],
    
    // Let's assume an ORDINARY section allows Videos and Articles
    [SectionType.ORDINARY]: [ResourceType.VIDEO, ResourceType.ARTICLE, ResourceType.MCQ], 
    
    // Future example: 
    // [SectionType.CODING_CHALLENGE]: [ResourceType.CODE_EDITOR, ResourceType.VIDEO],
};