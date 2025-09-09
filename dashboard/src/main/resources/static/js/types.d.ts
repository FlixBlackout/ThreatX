// Browser API type definitions for ThreatX Dashboard

// Fetch API
declare function fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;

declare interface RequestInfo {
    url?: string;
}

declare interface RequestInit {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
}

declare interface Response {
    ok: boolean;
    status: number;
    statusText: string;
    json(): Promise<any>;
    text(): Promise<string>;
}

// Chart.js
declare class Chart {
    constructor(ctx: any, config: any);
    destroy(): void;
    update(): void;
}

// Bootstrap
declare namespace bootstrap {
    class Modal {
        constructor(element: Element);
        show(): void;
        hide(): void;
    }
    class Tooltip {
        constructor(element: Element);
    }
}

// DOM APIs
declare var console: {
    log(...args: any[]): void;
    error(...args: any[]): void;
    warn(...args: any[]): void;
};

declare var document: {
    addEventListener(type: string, listener: EventListener): void;
    getElementById(id: string): Element | null;
    querySelector(selector: string): Element | null;
    querySelectorAll(selector: string): NodeList;
    createElement(tagName: string): Element;
    hidden: boolean;
};

declare var window: {
    fetch: typeof fetch;
    addEventListener(type: string, listener: EventListener): void;
    setInterval(callback: () => void, ms: number): number;
    clearInterval(id: number): void;
    setTimeout(callback: () => void, ms: number): number;
};

declare interface Element {
    textContent: string | null;
    innerHTML: string;
    className: string;
    classList: {
        add(token: string): void;
        remove(token: string): void;
    };
    addEventListener(type: string, listener: EventListener): void;
    parentNode: Node | null;
    remove(): void;
}

declare interface EventListener {
    (evt: Event): void;
}

declare interface Event {
    preventDefault(): void;
    target: EventTarget | null;
}

declare interface EventTarget {
    querySelector(selector: string): Element | null;
}

declare interface NodeList {
    forEach(callback: (value: Element, index: number) => void): void;
}

declare interface Node {
    appendChild(child: Node): Node;
}

// Date
declare class Date {
    constructor();
    constructor(value: string | number);
    toLocaleString(): string;
    toLocaleDateString(): string;
    toLocaleTimeString(): string;
    toISOString(): string;
}

// Promise
declare class Promise<T> {
    constructor(executor: (resolve: (value: T) => void, reject: (reason?: any) => void) => void);
    then<U>(onFulfilled?: (value: T) => U | Promise<U>): Promise<U>;
    catch<U>(onRejected?: (reason: any) => U | Promise<U>): Promise<U>;
    static all<T>(values: Promise<T>[]): Promise<T[]>;
    static resolve<T>(value: T): Promise<T>;
}

// JSON
declare var JSON: {
    parse(text: string): any;
    stringify(value: any): string;
};

// Global functions
declare function parseInt(string: string, radix?: number): number;
declare function parseFloat(string: string): number;
declare function isNaN(number: number): boolean;
declare function isFinite(number: number): boolean;