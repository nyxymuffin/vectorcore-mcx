package cms

import (
	"fmt"
	"strings"
)

// Partial document modification, RFC 4825 clauses 8.2.3 (creation), 8.2.4
// (replacement) and 8.2.5 (deletion): a PUT or DELETE whose URI carries a
// node selector modifies one element or attribute inside a stored document
// rather than the whole document.
//
// The parent-resolution rules of clause 8.2.1 apply: a missing document, an
// unresolvable parent, or a no-match node selector is a 409 carrying a
// <no-parent> conflict report; an attribute value that is not a legal
// AttValue is a 409 with <not-xml-att-value>; a fragment that cannot be
// placed is a 409 with <cannot-insert>.

// applyNodePut inserts or replaces the node addressed by the selector,
// returning the new document, whether the node already existed, and a
// conflict-report element name when the request must be refused.
func applyNodePut(document, selector, body, contentType string) (updated string, replaced bool, conflict string, err error) {
	steps, err := parseNodeSelector(selector)
	if err != nil {
		return "", false, "cannot-insert", err
	}
	last := steps[len(steps)-1]

	if last.attribute != "" {
		// Attribute PUT (clause 8.2.2): the body is an AttValue.
		value := strings.TrimSpace(body)
		if strings.ContainsAny(value, "<\"") {
			return "", false, "not-xml-att-value", fmt.Errorf("attribute value is not a legal AttValue")
		}
		parentSelector := joinSteps(steps[:len(steps)-1])
		parentRaw, _, found, err := selectNode(document, parentSelector)
		if err != nil || !found {
			return "", false, "no-parent", fmt.Errorf("parent node does not exist")
		}
		existing, had := attributeOf(parentRaw, last.attribute)
		_ = existing
		newParent, ok := setAttribute(parentRaw, last.attribute, value)
		if !ok {
			return "", false, "cannot-insert", fmt.Errorf("cannot set the attribute")
		}
		return strings.Replace(document, parentRaw, newParent, 1), had, "", nil
	}

	// Element PUT: the body must be a well-balanced fragment whose single
	// element matches the selector's last step.
	fragment := strings.TrimSpace(body)
	if !strings.HasPrefix(fragment, "<") || !strings.HasSuffix(fragment, ">") {
		return "", false, "cannot-insert", fmt.Errorf("body is not an XML fragment")
	}
	if name := fragmentElementName(fragment); last.name != "*" && !strings.EqualFold(name, last.name) {
		return "", false, "cannot-insert",
			fmt.Errorf("fragment element %q does not match the selector step %q", name, last.name)
	}

	// An existing target is replaced (clause 8.2.4).
	if existing, _, found, err := selectNode(document, selector); err == nil && found {
		return strings.Replace(document, existing, fragment, 1), true, "", nil
	}

	// Otherwise it is created inside the parent (clause 8.2.3): appended as
	// the last child, after any sibling of the same name.
	if len(steps) == 1 {
		return "", false, "no-parent", fmt.Errorf("the document root cannot be created by a node PUT")
	}
	parentSelector := joinSteps(steps[:len(steps)-1])
	parentRaw, _, found, err := selectNode(document, parentSelector)
	if err != nil || !found {
		return "", false, "no-parent", fmt.Errorf("parent node does not exist")
	}
	close := lastCloseTagIndex(parentRaw)
	if close < 0 {
		return "", false, "cannot-insert", fmt.Errorf("parent is not an element with content")
	}
	newParent := parentRaw[:close] + fragment + parentRaw[close:]
	return strings.Replace(document, parentRaw, newParent, 1), false, "", nil
}

// applyNodeDelete removes the addressed element or attribute (clause 8.2.5).
func applyNodeDelete(document, selector string) (updated string, found bool, conflict string, err error) {
	steps, err := parseNodeSelector(selector)
	if err != nil {
		return "", false, "cannot-insert", err
	}
	last := steps[len(steps)-1]

	if last.attribute != "" {
		parentSelector := joinSteps(steps[:len(steps)-1])
		parentRaw, _, ok, err := selectNode(document, parentSelector)
		if err != nil || !ok {
			return "", false, "no-parent", fmt.Errorf("parent node does not exist")
		}
		if _, had := attributeOf(parentRaw, last.attribute); !had {
			return "", false, "", nil // 404: nothing to delete
		}
		newParent := removeAttribute(parentRaw, last.attribute)
		return strings.Replace(document, parentRaw, newParent, 1), true, "", nil
	}

	existing, _, ok, err := selectNode(document, selector)
	if err != nil || !ok {
		return "", false, "", nil // 404: idempotent delete
	}
	return strings.Replace(document, existing, "", 1), true, "", nil
}

// joinSteps renders parsed steps back into a node selector.
func joinSteps(steps []nodeStep) string {
	var parts []string
	for _, st := range steps {
		if st.attribute != "" {
			parts = append(parts, "@"+st.attribute)
			continue
		}
		part := st.name
		switch {
		case st.attrName != "":
			part += fmt.Sprintf("[@%s=%q]", st.attrName, st.attrValue)
		case st.position > 0:
			part += fmt.Sprintf("[%d]", st.position)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "/")
}

// fragmentElementName returns the local name of a fragment's root element.
func fragmentElementName(fragment string) string {
	name := strings.TrimPrefix(fragment, "<")
	if i := strings.IndexAny(name, " \t\r\n/>"); i >= 0 {
		name = name[:i]
	}
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// lastCloseTagIndex returns the offset of an element's closing tag.
func lastCloseTagIndex(element string) int {
	i := strings.LastIndex(element, "</")
	if i < 0 {
		return -1
	}
	return i
}

// attributeOf reports an attribute's value on an element's open tag.
func attributeOf(element, name string) (string, bool) {
	end := strings.IndexByte(element, '>')
	if end < 0 {
		return "", false
	}
	tag := element[:end]
	needle := name + `="`
	i := strings.Index(tag, needle)
	if i < 0 {
		return "", false
	}
	rest := tag[i+len(needle):]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j], true
	}
	return "", false
}

// setAttribute sets or replaces an attribute on an element's open tag.
func setAttribute(element, name, value string) (string, bool) {
	end := strings.IndexByte(element, '>')
	if end < 0 {
		return "", false
	}
	tag := element[:end]
	needle := name + `="`
	if i := strings.Index(tag, needle); i >= 0 {
		rest := tag[i+len(needle):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			return "", false
		}
		return tag[:i+len(needle)] + value + rest[j:] + element[end:], true
	}
	selfClosing := strings.HasSuffix(strings.TrimSpace(tag), "/")
	insertAt := len(tag)
	if selfClosing {
		insertAt = strings.LastIndex(tag, "/")
	}
	return tag[:insertAt] + fmt.Sprintf(` %s=%q`, name, value) + tag[insertAt:] + element[end:], true
}

// removeAttribute drops an attribute from an element's open tag.
func removeAttribute(element, name string) string {
	end := strings.IndexByte(element, '>')
	if end < 0 {
		return element
	}
	tag := element[:end]
	needle := name + `="`
	i := strings.Index(tag, needle)
	if i < 0 {
		return element
	}
	rest := tag[i+len(needle):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return element
	}
	start := i
	for start > 0 && (tag[start-1] == ' ' || tag[start-1] == '\t') {
		start--
	}
	return tag[:start] + rest[j+1:] + element[end:]
}
