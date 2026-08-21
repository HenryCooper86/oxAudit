import {
  cloneElement,
  Fragment,
  isValidElement,
  useMemo,
  type ComponentProps,
  type ReactElement,
  type ReactNode,
} from "react";
import Markdown, { type Components } from "react-markdown";
import { normalizeSearchQuery, splitSearchMatches } from "../../lib/chatSearch";

function highlightNode(node: ReactNode, query: string): ReactNode {
  if (!query) return node;
  if (typeof node === "string") {
    return splitSearchMatches(node, query).map((segment, index) =>
      segment.match ? (
        <mark
          key={`${index}-${segment.text}`}
          data-chat-search-match
          className="chat-search-match"
        >
          {segment.text}
        </mark>
      ) : (
        segment.text
      ),
    );
  }
  if (Array.isArray(node)) {
    return node.map((child, index) => (
      <Fragment key={index}>{highlightNode(child, query)}</Fragment>
    ));
  }
  if (!isValidElement(node) || node.type === "mark") return node;
  const element = node as ReactElement<{ children?: ReactNode }>;
  if (element.props.children === undefined) return node;
  return cloneElement(element, undefined, highlightNode(element.props.children, query));
}

type MarkdownProps<T extends keyof React.JSX.IntrinsicElements> =
  ComponentProps<T> & { node?: unknown };

function markdownComponents(query: string): Components {
  const P = ({ node: _node, children, ...props }: MarkdownProps<"p">) => (
    <p {...props}>{highlightNode(children, query)}</p>
  );
  const Li = ({ node: _node, children, ...props }: MarkdownProps<"li">) => (
    <li {...props}>{highlightNode(children, query)}</li>
  );
  const H1 = ({ node: _node, children, ...props }: MarkdownProps<"h1">) => (
    <h1 {...props}>{highlightNode(children, query)}</h1>
  );
  const H2 = ({ node: _node, children, ...props }: MarkdownProps<"h2">) => (
    <h2 {...props}>{highlightNode(children, query)}</h2>
  );
  const H3 = ({ node: _node, children, ...props }: MarkdownProps<"h3">) => (
    <h3 {...props}>{highlightNode(children, query)}</h3>
  );
  const H4 = ({ node: _node, children, ...props }: MarkdownProps<"h4">) => (
    <h4 {...props}>{highlightNode(children, query)}</h4>
  );
  const Blockquote = ({ node: _node, children, ...props }: MarkdownProps<"blockquote">) => (
    <blockquote {...props}>{highlightNode(children, query)}</blockquote>
  );
  const Td = ({ node: _node, children, ...props }: MarkdownProps<"td">) => (
    <td {...props}>{highlightNode(children, query)}</td>
  );
  const Th = ({ node: _node, children, ...props }: MarkdownProps<"th">) => (
    <th {...props}>{highlightNode(children, query)}</th>
  );
  const Code = ({ node: _node, children, ...props }: MarkdownProps<"code">) => (
    <code {...props}>{highlightNode(children, query)}</code>
  );
  return { p: P, li: Li, h1: H1, h2: H2, h3: H3, h4: H4, blockquote: Blockquote, td: Td, th: Th, code: Code };
}

export function HighlightedText({ text, query }: { text: string; query: string }) {
  return <>{highlightNode(text, normalizeSearchQuery(query))}</>;
}

export function SearchableMarkdown({ content, query }: { content: string; query: string }) {
  const normalizedQuery = normalizeSearchQuery(query);
  const components = useMemo(
    () => markdownComponents(normalizedQuery),
    [normalizedQuery],
  );
  return <Markdown components={components}>{content}</Markdown>;
}
