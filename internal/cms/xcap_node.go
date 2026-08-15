package cms

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// XCAP node selectors, IETF RFC 4825 clauses 6.3 and 7: a document URI may be
// followed by "/~~/" and a node selector addressing one element or attribute
// inside the document. Element results are served as application/xcap-el+xml,
// attribute results as application/xcap-att+xml, and a selector that matches
// nothing is a 404 (clause 8.2.1).
//
// Namespace bindings from the query component (the xmlns() expressions of
// clause 6.4) are accepted but matching is by local name: the generated
// documents use a single default namespace per document, so prefix-to-URI
// disambiguation has nothing to distinguish.

const nodeSelectorSeparator = "/~~/"

// splitNodeSelector separates a document selector from its node selector.
func splitNodeSelector(path string) (string, string) {
	if i := strings.Index(path, nodeSelectorSeparator); i >= 0 {
		return path[:i], strings.Trim(path[i+len(nodeSelectorSeparator):], "/")
	}
	return path, ""
}

// xmlTreeNode is one element of a parsed document, with the byte range of its
// original serialization so selected fragments are returned verbatim.
type xmlTreeNode struct {
	local    string
	attrs    []xml.Attr
	children []*xmlTreeNode
	raw      string
}

// parseXMLTree builds the element tree of a document, recording each
// element's raw source text.
func parseXMLTree(body string) (*xmlTreeNode, error) {
	dec := xml.NewDecoder(strings.NewReader(body))
	var stack []*xmlTreeNode
	var starts []int64
	var root *xmlTreeNode
	for {
		before := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			if root != nil && errors.Is(err, io.EOF) {
				return root, nil
			}
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			node := &xmlTreeNode{local: t.Name.Local, attrs: append([]xml.Attr(nil), t.Attr...)}
			if len(stack) > 0 {
				stack[len(stack)-1].children = append(stack[len(stack)-1].children, node)
			} else if root == nil {
				root = node
			}
			stack = append(stack, node)
			starts = append(starts, before)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("unbalanced end element %q", t.Name.Local)
			}
			node := stack[len(stack)-1]
			node.raw = body[starts[len(starts)-1]:dec.InputOffset()]
			stack = stack[:len(stack)-1]
			starts = starts[:len(starts)-1]
			if len(stack) == 0 {
				return root, nil
			}
		}
	}
}

// nodeStep is one parsed step of a node selector: an element name test with
// an optional position or attribute predicate, or a terminal attribute step.
type nodeStep struct {
	attribute string // set for a terminal @name step
	name      string // local name, or "*"
	position  int    // 1-based, 0 if absent
	attrName  string // [@name="value"] predicate
	attrValue string
}

// parseNodeSelector splits a node selector into steps per RFC 4825 clause
// 6.3. The path arrives percent-decoded (net/http decodes the URL path), so
// predicates appear in their bracketed source form.
func parseNodeSelector(selector string) ([]nodeStep, error) {
	var steps []nodeStep
	for _, part := range strings.Split(selector, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "@") {
			steps = append(steps, nodeStep{attribute: part[1:]})
			continue
		}
		step := nodeStep{}
		name := part
		if i := strings.IndexByte(part, '['); i >= 0 {
			if !strings.HasSuffix(part, "]") {
				return nil, fmt.Errorf("malformed predicate in step %q", part)
			}
			name = part[:i]
			pred := part[i+1 : len(part)-1]
			if strings.HasPrefix(pred, "@") {
				eq := strings.Index(pred, "=")
				if eq < 0 {
					return nil, fmt.Errorf("malformed attribute predicate %q", pred)
				}
				step.attrName = pred[1:eq]
				step.attrValue = strings.Trim(pred[eq+1:], `"'`)
			} else {
				n, err := strconv.Atoi(pred)
				if err != nil || n < 1 {
					return nil, fmt.Errorf("malformed position predicate %q", pred)
				}
				step.position = n
			}
		}
		// Prefixes only disambiguate namespaces, which local-name matching
		// does not need.
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" {
			return nil, fmt.Errorf("empty element name in step %q", part)
		}
		step.name = name
		steps = append(steps, step)
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("empty node selector")
	}
	return steps, nil
}

func (n *xmlTreeNode) attr(name string) (string, bool) {
	for _, a := range n.attrs {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

func stepMatches(node *xmlTreeNode, step nodeStep) bool {
	if step.name != "*" && node.local != step.name {
		return false
	}
	if step.attrName != "" {
		v, ok := node.attr(step.attrName)
		if !ok || v != step.attrValue {
			return false
		}
	}
	return true
}

// selectNode resolves a node selector against a document. It returns the
// element's raw XML, or an attribute value with isAttr set, or ok=false when
// nothing matches.
func selectNode(body, selector string) (result string, isAttr bool, ok bool, err error) {
	steps, err := parseNodeSelector(selector)
	if err != nil {
		return "", false, false, err
	}
	root, err := parseXMLTree(body)
	if err != nil || root == nil {
		return "", false, false, fmt.Errorf("document not well-formed: %v", err)
	}

	// The first step names the document root.
	if steps[0].attribute != "" {
		return "", false, false, fmt.Errorf("node selector cannot start with an attribute")
	}
	if !stepMatches(root, steps[0]) || (steps[0].position > 1) {
		return "", false, false, nil
	}
	current := root
	for _, step := range steps[1:] {
		if step.attribute != "" {
			v, found := current.attr(step.attribute)
			if !found {
				return "", false, false, nil
			}
			return v, true, true, nil
		}
		matchIndex := 0
		var next *xmlTreeNode
		for _, child := range current.children {
			if !stepMatches(child, step) {
				continue
			}
			matchIndex++
			if step.position == 0 || step.position == matchIndex {
				next = child
				break
			}
		}
		if next == nil {
			return "", false, false, nil
		}
		current = next
	}
	return current.raw, false, true, nil
}

// xcapErrorBody builds an application/xcap-error+xml document (RFC 4825
// clause 11.2) with the given condition element.
func xcapErrorBody(condition, phrase string) string {
	attr := ""
	if phrase != "" {
		attr = fmt.Sprintf(" phrase=%q", xmlText(phrase))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<xcap-error xmlns="urn:ietf:params:xml:ns:xcap-error"><%s%s/></xcap-error>`, condition, attr)
}

// defaultXCAPCaps is the xcap-caps document of RFC 4825 clause 12, listing
// the application usages this server serves.
func defaultXCAPCaps() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<xcap-caps xmlns="urn:ietf:params:xml:ns:xcap-caps">
  <auids>
    <auid>xcap-caps</auid>
    <auid>org.3gpp.mcptt.ue-init-config</auid>
    <auid>org.3gpp.mcptt.ue-config</auid>
    <auid>org.3gpp.mcptt.user-profile</auid>
    <auid>org.3gpp.mcptt.service-config</auid>
    <auid>org.openmobilealliance.groups</auid>
  </auids>
  <extensions/>
  <namespaces>
    <namespace>urn:ietf:params:xml:ns:xcap-caps</namespace>
    <namespace>urn:3gpp:mcptt:mcpttUEinitConfig:1.0</namespace>
    <namespace>urn:3gpp:mcptt:mcpttUEConfig:1.0</namespace>
    <namespace>urn:3gpp:mcptt:user-profile:1.0</namespace>
    <namespace>urn:3gpp:ns:mcpttServiceConfig:1.0</namespace>
    <namespace>urn:oma:xml:poc:list-service</namespace>
    <namespace>urn:3gpp:ns:mcpttGroupInfo:1.0</namespace>
  </namespaces>
</xcap-caps>`
}
